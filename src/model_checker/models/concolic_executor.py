import angr
import claripy
import os
from contextlib import contextmanager

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


def _wide_load(state, addr):
    return state.memory.load(addr, 4, endness="Iend_LE")


class _Wcscpy(angr.SimProcedure):
    """wcscpy for glibc's four-byte wchar_t; angr ships no wide-string procedures."""

    def run(self, dst, src):
        for index in range(4096):
            wchar = _wide_load(self.state, src + index * 4)
            self.state.memory.store(dst + index * 4, wchar, endness="Iend_LE")
            if self.state.solver.is_true(wchar == 0):
                break
        return dst


class _Wcscat(angr.SimProcedure):
    def run(self, dst, src):
        end = 0
        while end < 4096 and not self.state.solver.is_true(_wide_load(self.state, dst + end * 4) == 0):
            end += 1
        for index in range(4096):
            wchar = _wide_load(self.state, src + index * 4)
            self.state.memory.store(dst + (end + index) * 4, wchar, endness="Iend_LE")
            if self.state.solver.is_true(wchar == 0):
                break
        return dst


class _Wmemcpy(angr.SimProcedure):
    """wmemcpy/wmemmove/wcsncpy: copy n wide characters (wcsncpy padding is the same size)."""

    def run(self, dst, src, count):
        n = min(self.state.solver.max_int(count), 4096)
        if n:
            self.state.memory.store(dst, self.state.memory.load(src, n * 4))
        return dst


class _Wmemset(angr.SimProcedure):
    def run(self, dst, wchar, count):
        n = min(self.state.solver.max_int(count), 4096)
        for index in range(n):
            self.state.memory.store(dst + index * 4, wchar[31:0], endness="Iend_LE")
        return dst


# Library functions whose stack writes matter, executed with real semantics
# while a call is summarized (they are ReturnUnconstrained stubs otherwise).
_WRITING_PROCEDURES = {
    name: angr.SIM_PROCEDURES["libc"][name]
    for name in (
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsnprintf", "gets", "fgets", "scanf", "sscanf",
    )
    if name in angr.SIM_PROCEDURES["libc"]
}
_WRITING_PROCEDURES.update({
    name: angr.SIM_PROCEDURES["posix"][name] for name in ("read", "recv") if name in angr.SIM_PROCEDURES["posix"]
})
_WRITING_PROCEDURES.update({
    "wcscpy": _Wcscpy, "wcscat": _Wcscat, "wcsncpy": _Wmemcpy,
    "wmemcpy": _Wmemcpy, "wmemmove": _Wmemcpy, "wmemset": _Wmemset,
})


def _plt_function_name(name):
    name = name.split("@", 1)[0]
    for prefix in ("__isoc99_", "__isoc23_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name


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
        cache_key = (id(project), start_addr, target_addr, cls._hook_fingerprint(project))
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
    def _hook_fingerprint(project):
        """States reached under different hooks are not interchangeable."""
        return frozenset(
            (addr, type(procedure).__name__)
            for addr, procedure in project._sim_procedures.items()
        )

    @staticmethod
    @contextmanager
    def real_libc_procedures(project):
        """Temporarily give writing libc functions real semantics instead of stubs."""
        replaced = []
        for name, addr in project.loader.main_object.plt.items():
            procedure = _WRITING_PROCEDURES.get(_plt_function_name(name))
            if procedure is None:
                continue
            replaced.append((addr, project.hooked_by(addr) if project.is_hooked(addr) else None))
            project.hook(addr, procedure(), replace=True)
        try:
            yield
        finally:
            for addr, previous in replaced:
                project.unhook(addr)
                if previous is not None:
                    project.hook(addr, previous)

    @staticmethod
    def run_call_recording_writes(project, state, return_addr, region_low, region_high, step_limit=None):
        """
        Execute the call instruction at ``state`` until it returns to
        ``return_addr`` and collect every byte address in
        [region_low, region_high) written by any explored path.

        Returns (written_addresses, returned_state); returned_state is None
        when no path returned but writes were observed.
        """
        written = set()

        def record_write(write_state):
            address = write_state.inspect.mem_write_address
            if address is None:
                return
            length = write_state.inspect.mem_write_length
            if length is None:
                expr = write_state.inspect.mem_write_expr
                length = expr.length // 8 if expr is not None else 1
            try:
                if not isinstance(length, int):
                    length = write_state.solver.max_int(length)
                starts = (
                    [address.concrete_value] if address.concrete
                    else write_state.solver.eval_upto(address, 16)
                )
            except Exception:
                return
            for start in starts:
                for byte_address in range(start, start + max(1, min(int(length), 1 << 16))):
                    if region_low <= byte_address < region_high:
                        written.add(byte_address)

        state = state.copy()
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=record_write)
        call_sp = state.solver.eval(state.regs.rsp)
        if step_limit is None:
            step_limit = global_vars.CONCOLIC_STEP_LIMIT

        simgr = project.factory.simgr(state)
        returned = []
        extra_steps = None
        for _ in range(step_limit):
            if not simgr.active:
                break
            try:
                simgr.step()
            except TypeError as exc:
                raise FailedConcolicExecution(f"angr failed while stepping: {exc}") from exc
            still_running = []
            for active_state in simgr.active:
                if not active_state.ip.concrete:
                    continue
                if active_state.addr == return_addr and active_state.solver.eval(active_state.regs.rsp) == call_sp:
                    returned.append(active_state)
                else:
                    still_running.append(active_state)
            simgr.stashes["active"] = still_running[:global_vars.CONCOLIC_ACTIVE_LIMIT]
            # Let sibling paths finish briefly once one path has returned.
            if returned:
                extra_steps = 64 if extra_steps is None else extra_steps - 1
                if extra_steps <= 0:
                    break
        if not returned:
            # A callee that smashes its own return address never comes back;
            # the writes it made on the way are still what we need.
            if written:
                return written, None
            raise FailedConcolicExecution(f"Call did not return to {hex(return_addr)}")
        return written, returned[0]

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
