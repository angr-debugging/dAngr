
from dAngr.exceptions import DebuggerCommandError
from .base import BaseCommand
from .filters import FilterCommands
from dAngr.angr_ext.filters import AddressFilter, Filter, FunctionFilter

class BreakpointCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        
    def add_breakpoint(self, address:int):  # type: ignore
        """
        Set a breakpoint at a given address.
    
        Args:
            address (int): Address to set the breakpoint at.
        
        Short name: ba
        """
        f = FilterCommands(self.debugger).by_address(address)
        self.debugger.breakpoints.append(f)
        self.send_info(f"Address {hex(address)} added to breakpoints.")
    
    def add_breakpoint_at_line(self, source_file: str, line: int):  # type: ignore
        """
        Set a breakpoint at a given line of a source file. Requires debug symbols to be loaded.
    
        Args:
            source_file (str): Source file to set the breakpoint at.
            line (int): Line number to set the breakpoint at.
        
        Short name: bal
        """
        f = FilterCommands(self.debugger).by_line(source_file, line)
        self.debugger.breakpoints.append(f)
        self.send_info(f"Address {hex(f.address)} added to breakpoints.")
    
    def add_breakpoint_at_function(self, function: str):  # type: ignore
        """
        Set a breakpoint at a given function. Requires debug symbols to be loaded.
    
        Args:
            function (str): Function to set the breakpoint at.
        
        Short name: baf
        """
        f = FilterCommands(self.debugger).by_function(function)
        self.debugger.breakpoints.append(f)
        self.send_info(f"Function {function} added to breakpoints.")
    
    def remove_breakpoint(self, address:int):  # type: ignore
        """
        Remove a breakpoint at a given address.
    
        Args:
            address (int): Address to remove the breakpoint from.
        
        Short name: bra
        """

        f = self.debugger.breakpoints.find(AddressFilter, lambda f: f.address == address) # type: ignore
        if f is None:
            self.send_error(f"Breakpoint at address {hex(address)} not found.")
            return
        self.debugger.breakpoints.remove(f)
        self.send_info(f"Address {hex(address)} removed from breakpoints.")

    
    def remove_breakpoint_at_line(self, source_file: str, line: int):  # type: ignore
        """
        Remove a breakpoint at a given line of a source file. Requires debug symbols to be loaded.
    
        Args:
            source_file (str): Source file to remove the breakpoint from.
            line (int): Line number to remove the breakpoint from.
        
        Short name: brl
        """
        address = self.debugger.find_address(source_file, line)
        if address is None:
            self.send_error(f"Breakpoint at {source_file}:{line} not found.")
            return
        f = self.debugger.breakpoints.find(FunctionFilter, lambda f: f.f_addr == address)
        if f is None:
            self.send_error(f"Breakpoint at {source_file}:{line} not found.")
            return
        self.debugger.breakpoints.remove(f)
        self.send_info(f"Address {hex(address)} removed from breakpoints.")
    
    def remove_breakpoint_at_function(self, function: str):  # type: ignore
        """
        Remove a breakpoint at a given function. Requires debug symbols to be loaded.
    
        Args:
            function (str): Function to remove the breakpoint from.
        
        Short name: brfun
        """
        address = self.debugger.get_function_address(function)
        f = self.debugger.breakpoints.find(FunctionFilter, lambda f: f.f_addr == address)
        if f is None:
            self.send_error(f"Breakpoint at function {function} not found.")
            return
        self.debugger.breakpoints.remove(f)
        self.send_info(f"Function {function} removed from breakpoints.")

    def enable_breakpoint(self, index:int=0, enable:bool=True):
        """
        Enable filter at given index.

        Args:
            index (int): Index of the filter found using list_breakpoints.
            enable (bool): True to enable, False to disable.
        
        Short name: be
        """
        list = self.debugger.breakpoints
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        list[index].enabled = enable
        self.send_info(f"Breakpoint filter {'enabled' if enable else 'disabled'}.")
    def disable_breakpoint(self, index:int=0):
        """
        Disable filter at given index.

        Args:
            index (int): Index of the filter found using list_breakpoints.
        
        Short name: bd
        """
        list = self.debugger.breakpoints
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        list[index].enabled = False
        self.send_info(f"Breakpoint filter disabled.")

    def list_breakpoints(self):
        """
        List all breakpoints.
        
        Short name: bl
        """
        list = self.debugger.breakpoints
        if len(list) == 0:
            self.send_info(f'No breakpoints found.')
            return []
        breakpoint_str = "\n\t".join([f"[{i}] {b}" for i,b in enumerate(list)])
        return f'Breakpoint(s): {breakpoint_str}'
    
    def breakpoint(self, *filters:Filter):
            """
            Add a filter to the list of breakpoints.

            Args:
                filters (tuple): The filters to add. Can be an address, source file and line number, function name or stream text.
            
            Short name: bf
            """

            FilterCommands(self.debugger).filter(False, *filters)

    def remove_breakpoint_filter(self, index:int):
        """
        Remove a filter from the list of breakpoints.

        Args:
            index (int): Index of the filter found using list_filters.
        
        Short name: brf
        """
        FilterCommands(self.debugger).remove_filter(index, False)

    def clear_breakpoints(self):
        """
        Clear all breakpoints.

        Short name: bc
        """
        self.debugger.breakpoints.clear()
        self.send_info( "All breakpoints cleared.")