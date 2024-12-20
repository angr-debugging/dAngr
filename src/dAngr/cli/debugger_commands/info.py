import os



from .base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from prompt_toolkit.shortcuts import ProgressBar
from prompt_toolkit import ANSI

import angrutils

class InformationCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    def get_basicblocks(self):
        """
        Show the assembly for the current basic block.

        Requires Controlflow graph to be geenrated.
        Uses a progress bar to indicate the reconstruction of basic blocks.

        Short name: bbs
        """
        with ProgressBar(title="reconstructing basic blocks") as pb:
            for b in pb(self.debugger.get_bbs()):
                self.send_result(str(b))

    def get_current_block(self):
        """
        Show the current basic block.

        Returns:
            str: The current basic block.

        Raises:
            DebuggerCommandError: If no function is found with the given name.
        
        Short name: bb
        """
        b = self.debugger.get_current_basic_block()
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return b
    
    def get_cfg(self):
        """
        Show the control flow graph of the current function.

        Returns:
            str: The URL of the control flow graph.
        
        Short name: cfg
        """
        try:
            import pygraphviz as pgv # type: ignore
        except ImportError:
            raise DebuggerCommandError("Please install graphviz, graphviz-dev and pygraphviz to use this command.")

        cfg = self.debugger.cfg
        base_path = self.debugger.launch_file_server()
        file_index = 1 + len([name for name in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, name))])
        filename = "cfg_" + str(file_index)
        svg_path = f"{base_path}/{filename}"
        
        angrutils.plot_cfg(cfg, svg_path, asminst=True, vexinst=False, remove_imports=True, remove_path_terminator=True, format="svg")

        return f"http://localhost:8000/{filename}.svg"

    def verbose_step(self, enable:bool = True):
        """
        Enable or disable verbose stepping.

        Args:
            enable (bool): Enable or disable verbose stepping. Default True.

        Short name: vs
        """
        self.debugger.verbose_step = enable
        return f"Verbose stepping {'enabled' if enable else 'disabled'}."
    
    def get_stashes(self):
        """
        Get the available stashes.

        Returns:
            str: The available stashes.
        
        Short name: gs
        """
        return f"Stashes: {self.debugger.get_stashes()}"

    def list_states(self, stash:str = "active"):
        """
        List all active paths.

        Args:
            stash (str): The stash to use. Default active
        Returns:
            str: Information about the active paths.
        
        Short name: iap
        """
        paths = self.debugger.list_paths(stash) 
        result_list = []
        for i in range(len(paths)):
            result_list.append(f"{i}: " + str(paths[i]))
        return paths



    def list_binary_strings(self, min_length:int = 4):
        """
        List all binary strings.

        Args:
            min_length (int): The minimum length of the binary strings to list. Default 4.

        Returns:
            str: Information about the binary strings.
        
        Short name: ibstr
        """
        strings = self.debugger.get_binary_string_constants(min_length=min_length)
        return f"\taddress\tvalue\n{"\n".join([f"{s[0]}\t{s[1]}" for s in strings])}"

    def list_binary_symbols(self): # type: ignore
        """
        List the debugsymbols when available.

        Returns:
            str: Information about the binary symbols.

        Short name: ibsym
        """
        symbols = self.debugger.get_binary_symbols()
        return f"Binary Symbols: {"\n".join([str(s) for s in symbols])}"

    def list_constraints(self):
        """
        List the current path's constraints and symbolic variables.

        Returns:
            str: Information about the constraints.

        Short name: ic
        """
        ctrs = self.debugger.get_constraints()
        return f"Constraints: {"\n".join([str(c) for c in ctrs])}"

    def list_path_history(self, index:int = 0, stash:str = "active"):
        """
        List the history of a path.

        Args:
            index (int): The index of the path to list the history of. Default active path.
            stash (str): The stash to use. Default active.

        Returns:
            str: Information about the path history.

        Raises:
            DebuggerCommandError: If the path index is invalid.
        
        Short name: iph
        """
        return f"Path History: {"\n".join([str(p) for p in self.debugger.list_path_history(index, stash)])}"
    
    def get_binary_info(self):
        """
        Get information about the binary.

        Returns:
            str: Information about the binary.

        Short name: ibi
        """
        info = self.debugger.get_binary_info()
        return "\n".join([f"{i}: {info[i]}" for i in info])
    
    def get_binary_security_features(self):
        """
        Get security features of the binary.

        Returns:
            str: Information about the security features.

        Short name: ibsf
        """
        info = self.debugger.get_binary_security_features()
        return "\n".join([f"{i}: {info[i]}" for i in info])
    

    def inspect_state(self):
        """
        Inspect the current state.

        Returns:
            str: Information about the current state.

        Short name: is
        """
        # Registers --> refactor list registers to format 'eax': 0x0...
        pstr_state = self.debugger.visualise_state()
        self.send_result(ANSI(pstr_state))
    
# Add current basic block, current function + code
# Name of the symbolic var instead of the to str
# Parcially symbolic...
# Legende