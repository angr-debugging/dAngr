import os


import math
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
    
    def get_basicblock_at(self, addr:int):
        """
        Show the basic block at the given address.

        Args:
            addr (int): Address of the basic block.

        Returns:
            str: The basic block at the given address.

        Raises:
            DebuggerCommandError: If no basic block is found at the given address.
        
        Short name: bba
        """
        b = self.debugger.get_basic_block_at(addr)
        if b is None:
            raise DebuggerCommandError(f"No basic block found at address {hex(addr)}.")
        return b
    
    def get_size_basicblock(self, addr:int):
        """
        Get the size of a basic block.

        Args:
            addr (int): Address of the basic block.

        Returns:
            int: The size of the basic block.

        Short name: bbsz
        """
        b = self.debugger.get_basic_block_at(addr)
        return b.size
    
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

    def list_binary_strings(self,filter:str="",page_size:int=200,page_index:int=0, min_length:int = 4):
        """
        List all binary strings.

        Args:
            filter (str): List the strings containing the filtered value (optional).
            page_size (int): The amount of strings to return (default: 200).
            page_index (int): The page of the strings that is returned (default: 0).
            min_length (int): The minimum length of the binary strings to list (default 4).

        Returns:
            str: The found strings in the binary and the addressess of these strings.
        
        Short name: ibstr
        """
        strings = self.debugger.get_binary_string_constants(filter, min_length=min_length)
        if page_index < 0:
            page_index = 0
        
        page_end = page_size*(page_index +1)
        max_index = len(strings) if page_end > len(strings) else page_end

        strings_filtered = strings[page_size*page_index:max_index]

        binary_strings = "\n".join([f"{s[0]}\t{s[1]}" for s in strings_filtered])
        return f"\taddress\tvalue (page {page_index}/{math.floor(len(strings)/page_size)})\n{binary_strings}"
    
    def list_binary_functions(self, filter:str="", page_size:int=200, page_index:int=0):
        """
        Lists the functions contained in the binary.
        
        Args:
            filter (str): Filter functions that contain this string value (optional)
            page_size (int): Amount of functions to return per page (default 200).
            page_index (int): page index to return (default 0).
        
        Short name: lbf
        """
        functions = self.debugger.list_functions()
        start_index = page_size*page_index
        end_index = page_size*(page_index+1)
        if filter != "":
            functions = [fn for fn in functions if filter in fn.name]


        end_index = end_index if end_index > start_index and end_index <= len(functions) else len(functions)
        start_index = start_index if start_index > 0 and start_index < len(functions) else 0
        fn_info = [(fn.addr, fn.name) for fn in functions[start_index:end_index]]

        functions_str = "\n".join([f"{hex(fn[0])}\t{fn[1]}" for fn in fn_info])

        return f"\taddress\tname (page: {page_index}/{math.floor(len(functions)/page_size)})\n{functions_str}"
        

    def list_binary_symbols(self): # type: ignore
        """
        List the debugsymbols when available.

        Returns:
            str: Information about the binary symbols.

        Short name: ibsym
        """
        symbols = self.debugger.get_binary_symbols()
        binary_symbols = "\n".join([str(s) for s in symbols])
        return f"Binary Symbols: {binary_symbols}"

    def list_binary_sections(self):
        """
        List all binary sections.

        Returns:
            str: Information about the binary sections.

        Short name: ibsec
        """
        sections = self.debugger.get_binary_sections()

        binary_sections = ""
        for s in sections:
            binary_sections += f"\n{s['name']}"
            binary_sections += f"\n\tregion: {s['min_addr']} - {s['max_addr']}"
            binary_sections += f"\n\tsize: {s['size']}"
            binary_sections += f"\n\tpermissions: "
            binary_sections += "r" if s['is_readable'] else "-"
            binary_sections += "w" if s['is_writable'] else "-"
            binary_sections += "x" if s['is_executable'] else "-"
        return f"{binary_sections}"


    def list_constraints(self):
        """
        List the current path's constraints and symbolic variables.

        Returns:
            str: Information about the constraints.

        Short name: ic
        """
        ctrs = self.debugger.get_constraints()
        constraints = "\n".join([str(c) for c in ctrs])
        return f"Constraints: {constraints}"

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
        path_string = "\n".join([str(p) for p in self.debugger.list_path_history(index, stash)])
        return f"Path History: {path_string}"
    
    def get_callstack(self):
        """
        Get the current callstack. Requires semantic callstack to be initialized.

        Returns:
            str: Information about the callstack.

        Short name: ccs
        """
        state = self.debugger.current_state
        callstack = self.debugger.get_callstack(state=state)
        return callstack
    
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
    
    def get_call_stack(self):
        """
        Get the current call stack.

        Returns:
            str: Information about the call stack.

        Short name: gcstack
        """
        call_stack = self.debugger.get_call_stack()
        stack_str = "\n"
        for frame in call_stack:
            if(frame.function_address != 0 and "State at address" not in frame.function_display_name):
                stack_str += f"Function: {frame.function_display_name} ({hex(frame.function_address)}) at {hex(frame.return_address)}\n"
        return stack_str

    def inspect_state(self):
        """
        Inspect the current state.

        Returns:
            str: Information about the current state.

        Short name: is
        """
        # Registers --> refactor list registers to format 'eax': 0x0...
        pstr_state = self.debugger.visualize_state()
        self.send_result(ANSI(pstr_state))

    def start_cfg_viewer(self):
        """
        Start the CFG viewer server.

        Returns:
            str: Information about the server.

        Short name: cfgs
        """
        base_path = self.debugger.launch_cfg_server()
        return f"File server started at http://localhost:8000/ serving files from {base_path}"
    
# Add current basic block, current function + code
# Name of the symbolic var instead of the to str
# Parcially symbolic...
# Legende