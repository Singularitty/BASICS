import angr
import claripy
import os

from src import global_vars
from src.exceptions import FailedConcolicExecution

_PAGESIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

def _rss_mb():
    """Return current RSS in MB by reading /proc/self/statm (Linux only, cheap)."""
    try:
        with open("/proc/self/statm") as f:
            rss_pages = int(f.read().split()[1])
        return rss_pages * _PAGESIZE / (1024 * 1024)
    except Exception:
        return 0.0


class ConcolicExecutor:
    """
    Small wrapper around angr for repeated reachability queries.

    BASICS asks angr the same expensive question many times: reach a call or
    loop address from the binary entry. Cache the pre-target state and copy it
    before mutation so function and loop summaries can reuse the same prefix.
    """

    _state_cache = {}

    @classmethod
    def entry_address(cls, project):
        if global_vars.ANALYSIS_START_ADDR is not None:
            return global_vars.ANALYSIS_START_ADDR
        main_addr = project.loader.main_object.get_symbol("main")
        return main_addr.rebased_addr if main_addr is not None else project.entry

    @classmethod
    def blank_entry_state(cls, project, start_addr=None):
        if start_addr is None:
            start_addr = cls.entry_address(project)
        kwargs = {
            "addr": start_addr,
            "add_options": {
                angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                # Exact-address reachability is checked between simgr steps.
                # Unicorn can execute across several basic blocks in one step
                # and skip the requested loop/call address entirely.
            },
        }
        if global_vars.ANGR_OPTION is not None:
            kwargs["mode"] = global_vars.ANGR_OPTION
        # A labelled Juliet analysis entry is a normal C function, not the ELF
        # process entry.  Starting it as a blank state leaves no return address;
        # after a helper returns, angr can follow an unconstrained target into
        # unrelated testcase-support code.  call_state supplies a valid ABI
        # frame and a dead-end return target while retaining the same options.
        analysis_start = global_vars.ANALYSIS_START_ADDR
        if analysis_start is not None and start_addr == analysis_start:
            state = project.factory.call_state(
                start_addr,
                ret_addr=project.simos.return_deadend,
                add_options=kwargs["add_options"],
                **({"mode": kwargs["mode"]} if "mode" in kwargs else {}),
            )
        else:
            state = project.factory.blank_state(**kwargs)
        if global_vars.DEBUG:
            print(
                f"Concolic entry state at {hex(start_addr)} mode={state.mode} "
                f"angr_option={global_vars.ANGR_OPTION!r} ip={state.regs.ip} "
                f"hooked={project.is_hooked(start_addr)}"
            )
        cls._constrain_scan_entry_args(state)
        return state

    @staticmethod
    def _constrain_scan_entry_args(state):
        """Avoid impossible function-entry callers that pass this frame's stack as an arg."""
        if not global_vars.SCAN_MODE or not global_vars.SCAN_CONSTRAIN_ARG_REGS:
            return
        try:
            sp = state.solver.eval(state.regs.rsp)
        except Exception:
            return
        guard = int(global_vars.SCAN_ARG_STACK_GUARD_BYTES or 0)
        if guard <= 0:
            return
        bits = state.arch.bits
        low = claripy.BVV(max(0, sp - guard), bits)
        high = claripy.BVV(sp + guard, bits)
        for reg_name in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
            if not hasattr(state.regs, reg_name):
                continue
            value = getattr(state.regs, reg_name)
            state.solver.add(claripy.Or(value < low, value > high))

    @classmethod
    def reaching_state(cls, project, target_addr, start_addr=None, step_limit=None):
        if start_addr is None:
            start_addr = cls.entry_address(project)
        cache_key = (id(project), start_addr, target_addr)
        if cache_key in cls._state_cache:
            return cls._state_cache[cache_key].copy()

        if step_limit is None:
            step_limit = global_vars.CONCOLIC_STEP_LIMIT

        entry_state = cls.blank_entry_state(project, start_addr)
        if global_vars.DEBUG:
            probe = project.factory.successors(entry_state.copy())
            print(
                "Concolic entry successors: "
                f"{[hex(state.addr) for state in probe.successors]}"
            )
        simgr = project.factory.simgr(entry_state)

        mem_limit = global_vars.SCAN_MEMORY_LIMIT_MB
        for step in range(step_limit):
            found = cls._find_target_state(simgr, target_addr)
            if found is not None:
                cls._state_cache[cache_key] = found.copy()
                return found.copy()
            if not simgr.active:
                break
            # Drop states with symbolic PC — they come from unresolved indirect
            # calls/jumps (function pointers) and will never reach a concrete target.
            simgr.stashes["active"] = [s for s in simgr.active if s.ip.concrete]
            if not simgr.active:
                break
            # Check RSS every 50 steps to avoid OOM on large binaries.
            if mem_limit is not None and step % 50 == 0:
                rss = _rss_mb()
                if rss > mem_limit:
                    raise FailedConcolicExecution(
                        f"Memory limit {mem_limit:.0f} MB exceeded ({rss:.0f} MB RSS)"
                    )
            simgr.stashes["active"] = sorted(
                simgr.active, key=lambda state: abs(state.addr - target_addr)
            )[:global_vars.CONCOLIC_ACTIVE_LIMIT]
            try:
                simgr.step()
                if global_vars.DEBUG and step < 3:
                    print(
                        f"Concolic reach step {step + 1}: "
                        f"{[(hex(state.addr), state.history.jumpkind) for state in simgr.active[:8]]}"
                    )
            except TypeError as exc:
                # Some unresolved libc stubs (notably strlen) can expose an
                # angr prototype/return-width mismatch.  Treat that path as an
                # unsuccessful concolic execution so callers can retry without
                # hooks or skip loop emulation instead of aborting the entire
                # binary analysis.
                raise FailedConcolicExecution(f"angr failed while stepping: {exc}") from exc

        active = ",".join(hex(state.addr) for state in simgr.active[:8]) or "none"
        raise FailedConcolicExecution(
            f"Could not reach {hex(target_addr)} from {hex(start_addr)}; "
            f"active={active}, deadended={len(simgr.deadended)}, "
            f"unconstrained={len(simgr.unconstrained)}, errored={len(simgr.errored)}"
        )

    @staticmethod
    def _find_target_state(simgr, target_addr):
        for state in simgr.active:
            if state.addr == target_addr:
                return state
        return None

    @classmethod
    def step_from_state(cls, project, state, steps=3):
        simgr = project.factory.simgr(state)
        for _ in range(steps):
            if not simgr.active:
                if simgr.unconstrained:
                    return simgr.unconstrained[0]
                raise FailedConcolicExecution("No active states after stepping from target")
            simgr.step()
            simgr.stashes["active"] = simgr.active[:global_vars.CONCOLIC_ACTIVE_LIMIT]
        if simgr.active:
            return simgr.active[0]
        if simgr.unconstrained:
            return simgr.unconstrained[0]
        raise FailedConcolicExecution("No post-target state available")

    @staticmethod
    def advance_instructions(project, state, instruction_count):
        if instruction_count <= 0:
            return state
        successors = project.factory.successors(state, num_inst=instruction_count)
        if successors.successors:
            return successors.successors[0]
        if successors.unconstrained_successors:
            return successors.unconstrained_successors[0]
        raise FailedConcolicExecution("No state available after intra-block stepping")
