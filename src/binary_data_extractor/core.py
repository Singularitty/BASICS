#imports
import os
import sys
import hashlib
import struct
import logging

# Work around angr LMDB spilling crashes on large/complex binaries.
# Keep these as defaults so users can still override via environment.
os.environ.setdefault("USE_SPILLING_CFGNODE_DICT", "False")
os.environ.setdefault("USE_SPILLING_FUNCTION_DICT", "False")
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

import angr
import cle
from angrutils import plot_cfg

def hook_return_0():
    return 0

class BinaryDataExtractor:

    def __init__(
        self,
        binary_path,
        cfg_emulated=True,
        cfg_mode=None,
        analysis_entry="main",
        cfg_fast_complete_scan=False,
        cfg_fast_resolve_indirect_jumps=True,
        cfg_fast_normalize=True,
        cfg_fast_function_starts_only=False,
        cfg_extra_starts=None,
    ) -> None:

        # Create Angr Project
        self.binary = os.path.realpath(os.path.abspath(binary_path))
        self.fingerprint = self.__fingerprint(self.binary)
        try:
            self.project = angr.Project(self.binary, load_options={'auto_load_libs': False}, exclude_sim_procedures_list=["free", "printf", "puts", "strlen",  "printf", "fprintf",
                                                                                                                            "fopen", "fclose", "fscanf", "strcmp", "system", "fread",
                                                                                                                            "exit", "time", "error", "perror", "fwrite", "printf_unlocked",
                                                                                                                            "puts_unlocked", "putchar_unlocked", "fputs_unlocked", "fputc_unlocked",
                                                                                                                            "fprintf_unlocked", "stack_chk_fail"])
        except cle.errors.CLECompatibilityError:
            print("Couldn't load binary with ELF backend, trying with blob backend")
            load_options = {'auto_load_libs': False, 'main_opts': {'backend': 'blob'}}
            try:
                self.project = angr.Project(self.binary, load_options=load_options)
            except Exception:
                print("Couldn't load binary")
                sys.exit(1)
            print("Loaded binary with blob backend")
            print("WARNING: Blob backend is not meant for binaries of unknown type and probably wont work")

        self.analysis_entry = analysis_entry
        self.analysis_entry_addr = self.resolve_analysis_entry(analysis_entry)
        self.cfg = self.build_cfg(
            cfg_emulated,
            cfg_mode,
            cfg_fast_complete_scan=cfg_fast_complete_scan,
            cfg_fast_resolve_indirect_jumps=cfg_fast_resolve_indirect_jumps,
            cfg_fast_normalize=cfg_fast_normalize,
            cfg_fast_function_starts_only=cfg_fast_function_starts_only,
            cfg_extra_starts=cfg_extra_starts,
        )
        self.functions = self.extract_user_functions()
        self.loops = self.find_loops()

        self.address_to_function = {}
        self.map_addresses_to_functions()

    def __fingerprint(self, path):
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                hasher.update(chunk)
        return {
            "path": path,
            "size": os.path.getsize(path),
            "sha256": hasher.hexdigest(),
        }

    def loader_summary(self):
        main_object = self.project.loader.main_object
        return {
            "binary": self.binary,
            "mapped_base": main_object.mapped_base,
            "min_addr": main_object.min_addr,
            "max_addr": main_object.max_addr,
            "entry": self.project.entry,
            "analysis_entry": self.analysis_entry,
            "analysis_entry_addr": self.analysis_entry_addr,
            "sections": len(list(main_object.sections)),
            "segments": len(list(main_object.segments)),
            "functions": len(self.cfg.kb.functions),
        }

    def resolve_analysis_entry(self, analysis_entry):
        if analysis_entry == "loader":
            return self.project.entry
        sym = self.project.loader.main_object.get_symbol(analysis_entry)
        if sym is not None:
            return sym.rebased_addr
        return self.project.entry

    def build_cfg(
        self,
        cfg_emulated,
        cfg_mode=None,
        cfg_fast_complete_scan=False,
        cfg_fast_resolve_indirect_jumps=True,
        cfg_fast_normalize=True,
        cfg_fast_function_starts_only=False,
        cfg_extra_starts=None,
    ):
        """
        Builds a CFG of the binary in the given project using angr's built-in analysis

        If cfg_emulated is True, the CFG will be built using angr's emulated CFG analysis
        Otherwise, the CFG will be built using angr's CFGFast analysis
        """
        start_addr = self.analysis_entry_addr
        starts = [start_addr]
        if cfg_extra_starts:
            starts.extend(int(addr) for addr in cfg_extra_starts if isinstance(addr, int))
        starts = list(dict.fromkeys(starts))
        if cfg_mode is None:
            cfg_mode = "emulated" if cfg_emulated else "fast"
        if cfg_mode == "auto":
            binary_size = os.path.getsize(self.binary)
            cfg_mode = "fast" if binary_size > 1 * 1024 * 1024 else "emulated"

        if cfg_mode == "emulated":
            initial_state = self.project.factory.blank_state(addr=start_addr)
            try:
                cfg = self.project.analyses.CFGEmulated(
                    fail_fast=True,
                    starts=starts,
                    initial_state=initial_state,
                )
            except (struct.error, TypeError) as err:
                # angr may crash in SpillingDiGraph serialization on some binaries.
                # Fall back to CFGFast so analysis can continue.
                print(
                    f"WARNING: CFGEmulated failed ({err}). "
                    "Falling back to CFGFast for this binary."
                )
                cfg_fast_kwargs = {
                    "force_complete_scan": cfg_fast_complete_scan,
                    "normalize": cfg_fast_normalize,
                    "resolve_indirect_jumps": cfg_fast_resolve_indirect_jumps,
                }
                if cfg_fast_function_starts_only or len(starts) > 1:
                    cfg_fast_kwargs["function_starts"] = starts
                cfg = self.project.analyses.CFGFast(**cfg_fast_kwargs)
        elif cfg_mode == "fast":
            cfg_fast_kwargs = {
                "force_complete_scan": cfg_fast_complete_scan,
                "normalize": cfg_fast_normalize,
                "resolve_indirect_jumps": cfg_fast_resolve_indirect_jumps,
            }
            if cfg_fast_function_starts_only or len(starts) > 1:
                cfg_fast_kwargs["function_starts"] = starts
            cfg = self.project.analyses.CFGFast(**cfg_fast_kwargs)
        else:
            raise ValueError(f"Invalid CFG mode: {cfg_mode}")
        return cfg

    def __is_user_function(self, function):
        """
        Returns True if the given function is a user-defined function
        """
        return not (function.is_plt or function.is_simprocedure)

    def find_loops(self):
        """
        Finds loops in the CFG
        """
        loops = self.project.analyses.LoopFinder()
        return loops.loops

    def extract_user_functions(self):
        """
        Extracts user-defined functions from the CFG
        """
        functions = [f for f in self.cfg.kb.functions.values() if self.__is_user_function(f)]
        return functions

    def draw_binary_cfg(self):
        """
        Draws the CFG of the binary
        """
        plot_cfg(self.cfg, f"cfg_{os.path.basename(self.binary)}", format="pdf", asminst=True, remove_imports=True, remove_path_terminator=True)

    def determine_function_name(self, ins):
        call_addr = ins.operands[0].imm
        for func in self.cfg.kb.functions.values():
            if func.addr == call_addr:
                return func.name
        return "Unknown Function"

    def map_addresses_to_functions(self):
        for func in self.cfg.kb.functions.values():
            if not func.is_plt and not func.is_simprocedure:
                for block in func.blocks:
                    for instruction in block.instruction_addrs:
                        self.address_to_function[instruction] = func.name
