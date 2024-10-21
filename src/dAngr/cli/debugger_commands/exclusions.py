from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter, AndFilterList, Filter, FilterFunction, FilterList, FunctionFilter, OrFilterList, SourceFilter, StdStreamFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError
from dAngr.utils.utils import StreamType

class ExclusionCommands(BaseCommand):

    def __init__(self, debugger:Debugger):
        super().__init__(debugger)

   
    async def add_exclusion(self, *filters:Filter):
        """
        Add a filter to the list of exclusions.

        Args:
            filters (tuple): The filters to add. Can be an address, source file and line number, function name or stream text.
        
        Short name: fae
        """
        if len(filters) == 0:
            raise DebuggerCommandError("At least one filter must be provided.")
        if len(filters) == 1:
            self.debugger.exclusions.append(filters[0])
        else:
            self.debugger.exclusions.append(AndFilterList([f for f in filters]))
        await self.send_info(f"{[str(f) for f in filters] if len(filters)>1 else str(filters[0])} added to exclusions.")

    
    async def remove_exclusion(self, index:int):
        """
        Remove a filter from the list of exclusions.

        Args:
            index (int): Index of the filter found using list_filters.
        
        Short name: re
        """
        list = self.debugger.exclusions
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        fltr = list.pop(index)
        await self.send_info(f"{fltr} removed from exclusions.")
    
    
    async def enable_exclusion(self, index:int=0, enable:bool=True):
        """
        Enable filter at given index.

        Args:
            index (int): Index of the filter found using list_exclusions.
            enable (bool): True to enable, False to disable.
        
        Short name: fe
        """
        list = self.debugger.exclusions
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        list[index].enabled = enable
        await self.send_info(f"Exclusion filter {'enabled' if enable else 'disabled'}.")

    
    async def list_exclusions(self):
        """
        List all exclusions.
        
        Short name: fl
        """
        list = self.debugger.exclusions
        if len(list) == 0:
            await self.send_info(f'No exclusions found.')
            return []
        return f'Exclusion(s): {"\n\t".join([f"[{i}] {b}" for i,b in enumerate(list)])}'
    
    
    async def clear_exclusions(self):
        """
        Clear all exclusions.

        Short name: fc
        """
        self.debugger.exclusions.clear()
        await self.send_info( "All exclusions cleared.")
