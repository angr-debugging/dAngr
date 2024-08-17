
from .base import BaseCommand
from .filters import FilterCommands

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
        await FilterCommands(self.debugger).filter(address)
    
    async def add_breakpoint_at_line(self, source_file: str, line: int):  # type: ignore
        """
        Set a breakpoint at a given line of a source file. Requires debug symbols to be loaded.
    
        Args:
            source_file (str): Source file to set the breakpoint at.
            line (int): Line number to set the breakpoint at.
        
        Short name: bal
        """
        await FilterCommands(self.debugger).filter_at_line(source_file, line)
    
    async def add_breakpoint_at_function(self, function: str):  # type: ignore
        """
        Set a breakpoint at a given function. Requires debug symbols to be loaded.
    
        Args:
            function (str): Function to set the breakpoint at.
        
        Short name: baf
        """
        await FilterCommands(self.debugger).filter_at_function(function)
    
    async def remove_breakpoint(self, address:int):  # type: ignore
        """
        Remove a breakpoint at a given address.
    
        Args:
            address (int): Address to remove the breakpoint from.
        
        Short name: br
        """
        await FilterCommands(self.debugger).filter(address, add=False)
    
    async def remove_breakpoint_at_line(self, source_file: str, line: int):  # type: ignore
        """
        Remove a breakpoint at a given line of a source file. Requires debug symbols to be loaded.
    
        Args:
            source_file (str): Source file to remove the breakpoint from.
            line (int): Line number to remove the breakpoint from.
        
        Short name: brl
        """
        await FilterCommands(self.debugger).filter_at_line(source_file, line, add=False)
    
    async def remove_breakpoint_at_function(self, function: str):  # type: ignore
        """
        Remove a breakpoint at a given function. Requires debug symbols to be loaded.
    
        Args:
            function (str): Function to remove the breakpoint from.
        
        Short name: brf
        """
        await FilterCommands(self.debugger).filter_at_function(function, add=False)
    
    async def clear_breakpoints(self):
        """
        Clear all breakpoints.

        Short name: bc
        """
        await FilterCommands(self.debugger).filter_clear(exclusions=False)
    
    async def disable_breakpoint(self, index: int):
        """
        Disable a breakpoint at a given index.
    
        Args:
            index (int): Index of the breakpoint to disable.

        Short name: bd
        """
        await FilterCommands(self.debugger).filter_enable(index, enable=False)
    
    async def enable_breakpoint(self, index: int, enable: bool = True):  # type: ignore
        """
        Enable or disable a breakpoint at a given index.
    
        Args:
            index (int): Index of the breakpoint to enable or disable.
            enable (bool): Flag to enable or disable the breakpoint. Default is True.

        Short name: be
        """
        await FilterCommands(self.debugger).filter_enable(index, enable)
    
    async def list_breakpoints(self):
        """
        List all breakpoints.

        Short name: bl
        """
        return await FilterCommands(self.debugger).filter_list()
