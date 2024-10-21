
from dAngr.exceptions import DebuggerCommandError
from .base import BaseCommand
from .filters import FilterCommands
from dAngr.cli.filters import AddressFilter, AndFilterList, Filter, FunctionFilter

class BreakpointCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        
    async def add_breakpoint(self, address:int):  # type: ignore
        """
        Set a breakpoint at a given address.
    
        Args:
            address (int): Address to set the breakpoint at.
        
        Short name: ba
        """
        f = await FilterCommands(self.debugger).address_filter(address)
        self.debugger.breakpoints.append(f)
        await self.send_info(f"Address {hex(address)} added to breakpoints.")
    
    async def add_breakpoint_at_line(self, source_file: str, line: int):  # type: ignore
        """
        Set a breakpoint at a given line of a source file. Requires debug symbols to be loaded.
    
        Args:
            source_file (str): Source file to set the breakpoint at.
            line (int): Line number to set the breakpoint at.
        
        Short name: bal
        """
        f = await FilterCommands(self.debugger).filter_at_line(source_file, line)
        self.debugger.breakpoints.append(f)
        await self.send_info(f"Address {hex(f.address)} added to breakpoints.")
    
    async def add_breakpoint_at_function(self, function: str):  # type: ignore
        """
        Set a breakpoint at a given function. Requires debug symbols to be loaded.
    
        Args:
            function (str): Function to set the breakpoint at.
        
        Short name: baf
        """
        f = await FilterCommands(self.debugger).filter_at_function(function)
        self.debugger.breakpoints.append(f)
        await self.send_info(f"Function {function} added to breakpoints.")
    
    async def remove_breakpoint(self, address:int):  # type: ignore
        """
        Remove a breakpoint at a given address.
    
        Args:
            address (int): Address to remove the breakpoint from.
        
        Short name: bra
        """

        f = self.debugger.breakpoints.find(AddressFilter, lambda f: f.address == address) # type: ignore
        if f is None:
            await self.send_error(f"Breakpoint at address {hex(address)} not found.")
            return
        self.debugger.breakpoints.remove(f)
        await self.send_info(f"Address {hex(address)} removed from breakpoints.")

    
    async def remove_breakpoint_at_line(self, source_file: str, line: int):  # type: ignore
        """
        Remove a breakpoint at a given line of a source file. Requires debug symbols to be loaded.
    
        Args:
            source_file (str): Source file to remove the breakpoint from.
            line (int): Line number to remove the breakpoint from.
        
        Short name: brl
        """
        address = self.debugger.find_address(source_file, line)
        if address is None:
            await self.send_error(f"Breakpoint at {source_file}:{line} not found.")
            return
        f = self.debugger.breakpoints.find(FunctionFilter, lambda f: f.f_addr == address)
        if f is None:
            await self.send_error(f"Breakpoint at {source_file}:{line} not found.")
            return
        self.debugger.breakpoints.remove(f)
        await self.send_info(f"Address {hex(address)} removed from breakpoints.")
    
    async def remove_breakpoint_at_function(self, function: str):  # type: ignore
        """
        Remove a breakpoint at a given function. Requires debug symbols to be loaded.
    
        Args:
            function (str): Function to remove the breakpoint from.
        
        Short name: brfun
        """
        address = self.debugger.get_function_address(function)
        f = self.debugger.breakpoints.find(FunctionFilter, lambda f: f.f_addr == address)
        if f is None:
            await self.send_error(f"Breakpoint at function {function} not found.")
            return
        self.debugger.breakpoints.remove(f)
        await self.send_info(f"Function {function} removed from breakpoints.")

    async def enable_breakpoint(self, index:int=0, enable:bool=True):
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
        await self.send_info(f"Breakpoint filter {'enabled' if enable else 'disabled'}.")
    async def disable_breakpoint(self, index:int=0):
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
        await self.send_info(f"Breakpoint filter disabled.")

    async def list_breakpoints(self):
        """
        List all breakpoints.
        
        Short name: bl
        """
        list = self.debugger.breakpoints
        if len(list) == 0:
            await self.send_info(f'No breakpoints found.')
            return []
        return f'Breakpoint(s): {"\n\t".join([f"[{i}] {b}" for i,b in enumerate(list)])}'
    
    async def add_breakpoint_filter(self, *filters:Filter):
            """
            Add a filter to the list of breakpoints.

            Args:
                filters (tuple): The filters to add. Can be an address, source file and line number, function name or stream text.
            
            Short name: bf
            """
            if len(filters) == 0:
                raise DebuggerCommandError("At least one filter must be provided.")
            if len(filters) == 1:
                self.debugger.breakpoints.append(filters[0])
            else:
                self.debugger.breakpoints.append(AndFilterList([f for f in filters]))
            await self.send_info(f"{[str(f) for f in filters] if len(filters)>1 else str(filters[0])} added to breakpoints.")

    async def remove_breakpoint_filter(self, index:int):
        """
        Remove a filter from the list of breakpoints.

        Args:
            index (int): Index of the filter found using list_filters.
        
        Short name: brf
        """
        list = self.debugger.breakpoints
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        fltr = list.pop(index)
        await self.send_info(f"{fltr} removed from breakpoints.")

    async def clear_breakpoints(self):
        """
        Clear all breakpoints.

        Short name: bc
        """
        self.debugger.breakpoints.clear()
        await self.send_info( "All breakpoints cleared.")