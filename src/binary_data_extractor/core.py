#imports
import angr
import cle
import os
import sys
import hashlib
from angrutils import plot_cfg

def hook_return_0():
    return 0

class BinaryDataExtractor:
    
    def __init__(self, binary_path, cfg_emulated = True, cfg_mode = None, analysis_entry = "main") -> None:
        
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
        self.cfg = self.build_cfg(cfg_emulated, cfg_mode)
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
        if analysis_entry != "main":
            raise ValueError(f"Invalid analysis entry: {analysis_entry}")
        main_addr = self.project.loader.main_object.get_symbol("main")
        return main_addr.rebased_addr if main_addr is not None else self.project.entry
        
    def build_cfg(self, cfg_emulated, cfg_mode = None):
        """
        Builds a CFG of the binary in the given project using angr's built-in analysis
        
        If cfg_emulated is True, the CFG will be built using angr's emulated CFG analysis
        Otherwise, the CFG will be built using angr's CFGFast analysis
        """
        start_addr = self.analysis_entry_addr
        if cfg_mode is None:
            cfg_mode = "emulated" if cfg_emulated else "fast"
        if cfg_mode == "auto":
            binary_size = os.path.getsize(self.binary)
            cfg_mode = "fast" if binary_size > 10 * 1024 * 1024 else "emulated"

        if cfg_mode == "emulated":
            initial_state = self.project.factory.blank_state(addr=start_addr)
            cfg = self.project.analyses.CFGEmulated(fail_fast=True, starts=[start_addr], initial_state=initial_state)
        elif cfg_mode == "fast":
            cfg = self.project.analyses.CFGFast(
                force_complete_scan=False,
                normalize=True,
                function_starts=[start_addr],
            )
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
