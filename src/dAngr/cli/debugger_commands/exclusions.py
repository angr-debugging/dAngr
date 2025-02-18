from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.debugger_commands.filters import FilterCommands
from dAngr.cli.filters import Filter
from dAngr.exceptions import DebuggerCommandError

class ExclusionCommands(BaseCommand):

    def __init__(self, debugger:Debugger):
        super().__init__(debugger)

    def add_exclusion(self, address:int):
        """
        Add an exclusion filter for a given address.

        Args:
            address (int): Address to exclude.
        
        Short name: exa
        """
        FilterCommands(self.debugger).filter(True, FilterCommands(self.debugger).by_address(address))

    def exclude(self, *filters:Filter):
        """
        Add a filter to the list of exclusions.

        Args:
            filters (tuple): The filters to add. Can be an address, source file and line number, function name or stream text.
        
        Short name: exaf
        """
        FilterCommands(self.debugger).filter(True, *filters)

    
    def remove_exclusion_filter(self, index:int):
        """
        Remove a filter from the list of exclusions.

        Args:
            index (int): Index of the filter found using list_filters.
        
        Short name: exr
        """
        FilterCommands(self.debugger).remove_filter(index, True)
    

    
    def enable_exclusion(self, index:int=0, enable:bool=True):
        """
        Enable filter at given index.

        Args:
            index (int): Index of the filter found using list_exclusions.
            enable (bool): True to enable, False to disable.
        
        Short name: exe
        """
        list = self.debugger.exclusions
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        list[index].enabled = enable
        self.send_info(f"Exclusion filter {'enabled' if enable else 'disabled'}.")

    
    def list_exclusions(self):
        """
        List all exclusions.
        
        Short name: exl
        """
        list = self.debugger.exclusions
        if len(list) == 0:
            self.send_info(f'No exclusions found.')
            return []
        exclusions_list = "\n\t".join([f"[{i}] {b}" for i,b in enumerate(list)])
        return f'Exclusion(s): {exclusions_list}'
    
    
    def clear_exclusions(self):
        """
        Clear all exclusions.

        Short name: fc
        """
        self.debugger.exclusions.clear()
        self.send_info( "All exclusions cleared.")
