#imports
import angr
import cle
import os
import sys
from angrutils import plot_cfg

def hook_return_0():
    return 0

class BinaryDataExtractor:
    
    def __init__(self, binary_path, cfg_emulated = True) -> None:
        
        # Create Angr Project
        self.binary = binary_path
        try:
            self.project = angr.Project(binary_path, load_options={'auto_load_libs': False}, exclude_sim_procedures_list=["free", "printf", "puts", "strlen",  "printf", "fprintf", 
                                                                                                                            "fopen", "fclose", "fscanf", "strcmp", "system", "fread",
                                                                                                                            "exit", "time", "error", "perror", "fwrite", "printf_unlocked", 
                                                                                                                            "puts_unlocked", "putchar_unlocked", "fputs_unlocked", "fputc_unlocked", 
                                                                                                                            "fprintf_unlocked", "stack_chk_fail"])
        except cle.errors.CLECompatibilityError:
            print("Couldn't load binary with ELF backend, trying with blob backend")
            load_options = {'auto_load_libs': False, 'main_opts': {'backend': 'blob'}}
            try:
                self.project = angr.Project(binary_path, load_options=load_options)
            except Exception:
                print("Couldn't load binary")
                sys.exit(1)
            print("Loaded binary with blob backend")
            print("WARNING: Blob backend is not meant for binaries of unknown type and probably wont work")
            
        
        self.cfg = self.build_cfg(cfg_emulated)
        self.functions = self.extract_user_functions()
        self.loops = self.find_loops()
        
        self.address_to_function = {}
        self.map_addresses_to_functions()
        
    def build_cfg(self, cfg_emulated):
        """
        Builds a CFG of the binary in the given project using angr's built-in analysis
        
        If cfg_emulated is True, the CFG will be built using angr's emulated CFG analysis
        Otherwise, the CFG will be built using angr's CFGFast analysis
        """
        main_addr = self.project.loader.main_object.get_symbol("main")
        initial_state = self.project.factory.blank_state(addr=main_addr.rebased_addr)
        if cfg_emulated:
            cfg = self.project.analyses.CFGEmulated(fail_fast=True, starts=[main_addr.rebased_addr], initial_state=initial_state)
        else:
            # For testing later
            cfg = self.project.analyses.CFGFast()
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