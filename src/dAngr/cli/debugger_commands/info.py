import os

from dAngr.cli.models import State
from .base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from prompt_toolkit.shortcuts import ProgressBar
import angrutils

class InformationCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    async def get_basicblocks(self):
        """
        Show the assembly for the current basic block.

        Requires Controlflow graph to be geenrated.
        Uses a progress bar to indicate the reconstruction of basic blocks.

        Short name: bbs
        """
        with ProgressBar(title="reconstructing basic blocks") as pb:
            for b in pb(self.debugger.get_bbs()):
                await self.send_result(str(b))

    async def get_current_block(self):
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
        return f"Current basic block: {b}"


    async def get_decompiled_function(self, function:str):  # type: ignore
        """
        Show the decompiled function.

        Args:
            function (str): The name of the function.

        Returns:
            str: The decompiled function.

        Raises:
            DebuggerCommandError: If no function is found with the given name.
        
        Short name: idf
        """
        b = self.debugger.get_decompiled_function(function)
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return f"{b}"
    
    async def get_decompiled_function_at_address(self, address:int):  # type: ignore
        """
        Show the decompiled function at a given address.

        Args:
            address (int): The address to decompile the function at.

        Returns:
            str: The decompiled function.

        Raises:
            DebuggerCommandError: If no function or basic block is found at the given address.
        short name: idfa
        """
        func = self.debugger.get_function_info(address)
        if func is None:
            raise DebuggerCommandError("No function found at this address.")
        b = self.debugger.get_decompiled_function(func.name)
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return f"{b}"

    async def get_function_info(self, function_name: str):
        """
        Get information about a function.

        Args:
            function_name (str): The name of the function.

        Returns:
            str: Information about the function.

        Raises:
            DebuggerCommandError: If no function is found with the given name.
        
        Short name: if
        """
        func = self.debugger.get_function_info(function_name)
        if func is None:
            raise DebuggerCommandError("No function found with this name.")
        return f"{func}"
    
    async def get_cfg(self):
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
    
   

    async def list_active_paths(self):
        """
        List all active paths.

        Returns:
            str: Information about the active paths.
        
        Short name: iap
        """
        paths = self.debugger.get_paths()
        return f"Paths Found: {"\n".join( [str(State(index, path.addr)) for index, path in enumerate(paths)])}"

    async def list_binary_strings(self, min_length:int = 4):
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

    async def list_binary_symbols(self): # type: ignore
        """
        List the debugsymbols when available.

        Returns:
            str: Information about the binary symbols.

        Short name: ibsym
        """
        symbols = self.debugger.get_binary_symbols()
        return f"Binary Symbols: {"\n".join([str(s) for s in symbols])}"

    async def list_constraints(self):
        """
        List the current path's constraints and symbolic variables.

        Returns:
            str: Information about the constraints.

        Short name: ic
        """
        ctrs = self.debugger.get_constraints()
        return f"Constraints: {"\n".join([str(c) for c in ctrs])}"

    async def list_path_history(self, index:int = 0, stash:str = "active"):
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