from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter, FunctionFilter, SourceFilter, StdStreamFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError
from dAngr.utils.utils import StreamType

class FilterCommands(BaseCommand):

    def __init__(self, debugger:Debugger):
        super().__init__(debugger)

    async def filter(self, address:int, avoid:bool=False, add:bool = True):
        """
        Set an address filter.

        Args:
            address (int): The address to filter on.
            avoid (bool): When instead of breaking you want to ignore the basic block.
            add (bool): Add or remove the address filter from the list.
        
        Short name: fa
        """
        list = self.debugger.exclusions if avoid else self.debugger.trigger_points
        if not add:
            fx = next((f for f in list if isinstance(f, AddressFilter) and f.address == address), None)
            if fx is None:
                raise DebuggerCommandError(f"{'Exclusion' if avoid else 'Breakpoint'} at address {hex(address)} not found.")
            list.remove(fx)
        else:
            if any(f.address == address for f in list if isinstance(f, AddressFilter)):
                raise DebuggerCommandError(f"{'Exclusion' if avoid else 'Breakpoint'} at address {hex(address)} already exists.")
            list.append(AddressFilter(address))
        await self.send_info(f"Address {hex(address)} {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")

    async def filter_at_line(self, source_file:str, line_nr:int, avoid:bool=False, add:bool = True):
        """
        Set a source line filter.

        Args:
            source_file (str): The source file to filter on.
            line_nr (int): The line number to filter on.
            avoid (bool): When instead of breaking you want to ignore the basic block.
            add (bool): Add or remove the source filter from the list.
        
        Short name: fal
        """
        address = self.debugger.find_address(source_file, line_nr)
        if address is None:
            raise DebuggerCommandError(f"No address found for {source_file}:{line_nr}.")
        list = self.debugger.exclusions if avoid else self.debugger.trigger_points
        if not add:
            list = [f for f in list if not isinstance(f, AddressFilter) or f.address != address]
        else:
            if any(f.address == address for f in list if isinstance(f, AddressFilter)):
                raise DebuggerCommandError(f"{'Exclusion' if avoid else 'Breakpoint'} at address {hex(address)} already exists.")
            list.append(SourceFilter(address, source_file, line_nr))
        await self.send_info(f"Address {hex(address)} {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")

    async def filter_at_function(self, name:str, avoid:bool = False, add:bool = True):
        """
        Set a function filter.

        Args:
            name (str): The name of the function on which you want to filter.
            avoid (bool): When instead of breaking you want to ignore the basic block.
            add (bool): Add or remove the function filter from the list.
        
        Short name: faf
        """
        if self.debugger.get_function_address(name) is None:
            raise DebuggerCommandError(f"Function {name} not found.")
        list = self.debugger.exclusions if avoid else self.debugger.trigger_points
        if not add:
            list = [f for f in list if not isinstance(f, FunctionFilter) or f.function_name != name]
        else:
            list.append(FunctionFilter(name))
        await self.send_info(f"Function {name} {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")

    async def filter_for_stream(self, text:str, avoid:bool=False, add:bool = True, stream:StreamType=StreamType.stdout):
        """
        Set a stream filter.

        Args:
            text (str): Text that must be in the stream.
            avoid (bool): When instead of breaking you want to ignore the basic block.
            add (bool): Add or remove the stream filter from the list.
            stream (StreamType): Stream to filter (i.e., stdin/stdout/stderr). Default 'stdout'.
        
        Short name: fas
        """
        list = self.debugger.exclusions if avoid else self.debugger.trigger_points
        if not add:
            list = [f for f in list if not isinstance(f, StdStreamFilter) or f.value != text]
        else:
            list.append(StdStreamFilter(stream.value, text))
        await self.send_info(f"Stream filter '{text}' {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")

    async def filter_clear(self, exclusions:bool=False):
        """
        Clear all breakpoints. If exclusions is set, remove all exclusions instead.

        Args:
            exclusions (bool): Whether the exclusion or breakpoint filters need to be cleared. Default True removes breakpoints.
        
        Short name: fc
        """
        if exclusions:
            self.debugger.exclusions.clear()
            await self.send_info( "All exclusions cleared.")
        else:
            self.debugger.trigger_points.clear()
            await self.send_info( "All breakpoints cleared.")

    async def filter_enable(self, index:int, enable:bool, exclusion:bool=False):
        """
        Enable filter at given index.

        Args:
            index (int): Index of the filter found using list_filters.
            enable (bool): True to enable, False to disable.
            exclusion (bool): Whether it is an exclusion or breakpoint filter. Default is breakpoint.
        
        Short name: fe
        """
        list = self.debugger.exclusions if exclusion else self.debugger.trigger_points
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        list[index].enabled = enable
        await self.send_info(f"{'Exclusion' if exclusion else 'Breakpoint'} filter {'enabled' if enable else 'disabled'}.")

    async def filter_list(self, exclusions:bool=False):
        """
        List all breakpoints. If exclusions is set (default: False), list all exclusions instead.

        Args:
            exclusions (bool): Whether the exclusion or breakpoint filters need to be listed. Default is breakpoint.
        
        Short name: fl
        """
        list = self.debugger.exclusions if exclusions else self.debugger.trigger_points
        if len(list) == 0:
            await self.send_info(f'No {"exclusions" if exclusions else "breakpoints"} set.')
            return []
        return f'{"Exclusion" if exclusions else "Breakpoint" }(s): {",".join([f"[{i}] {b}" for i,b in enumerate(list)])}'
