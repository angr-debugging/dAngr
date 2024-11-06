from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter, AndFilterList, Filter, FilterFunction, FilterList, FunctionFilter, OrFilterList, SourceFilter, StdStreamFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError
from dAngr.utils.utils import StreamType

class FilterCommands(BaseCommand):

    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        

    def filter(self, exclude:bool = False, *filters:Filter):
        """
        Add filters to the list of breakpoints or exclusions.

        Args:
            filters (tuple): The filters to add. Can be an address, source file and line number, function name or stream text.
            exclude (bool): True to add to exclusions, False to add to breakpoints.
        
        Short name: fae
        """
        if len(filters) == 0:
            raise DebuggerCommandError("At least one filter must be provided.")
        lst = self.debugger.exclusions if exclude else self.debugger.breakpoints
        if len(filters) == 1:
            lst.append(filters[0])
        else:
            lst.append(AndFilterList([f for f in filters]))
        self.send_info(f"{[str(f) for f in filters] if len(filters)>1 else str(filters[0])} added to {'exclusions' if exclude else 'breakpoints'}.")

    def remove_filter(self, index:int, exclude:bool = False):
        """
        Remove a filter from the list of breakpoints or exclusions.

        Args:
            index (int): Index of the filter found using list_filters.
            exclude (bool): True to remove from exclusions, False to remove from breakpoints.
        
        Short name: re
        """
        lst = self.debugger.exclusions if exclude else self.debugger.breakpoints
        if index >= len(lst):
            raise DebuggerCommandError(f"Index {index} out of range.")
        fltr = lst.pop(index)
        self.send_info(f"{fltr} removed from {'exclusions' if exclude else 'breakpoints'}.")

    def make_filter(self, function:str):
        """
        Add a filtering method. A method which returns a boolean value to indicate that the filter matches or not. When the method returns True, the filter matches and the breakpoint is triggered.

        Args:
            function (str): Name of the filter function.
        
        Short name: fm
        """
        func = self.debugger.context.get_definition(function)
        return FilterFunction(func, debugger=self.debugger)
    
    def or_filters(self, *filters:Filter):
        """
        Add an OR filter.

        Args:
            filters (tuple): The filters to OR.
        
        Short name: f_or
        """
        return OrFilterList([f for f in filters])
    def and_filters(self, *filters:Filter):
        """
        Add an AND filter.

        Args:
            filters (tuple): The filters to AND.
        
        Short name: f_and
        """
        return AndFilterList([f for f in filters])
    
    def by_address(self, address:int):
        """
        Add an address filter.

        Args:
            address (int): Address to filter on.
        
        Short name: fa
        """
        return AddressFilter(address)

    def by_line(self, source_file:str, line_nr:int):
        """
        Set a source line filter.

        Args:
            source_file (str): The source file to filter on.
            line_nr (int): The line number to filter on.
        
        Short name: fline
        """
        address = self.debugger.find_address(source_file, line_nr)
        if address is None:
            raise DebuggerCommandError(f"No address found for {source_file}:{line_nr}.")
        return SourceFilter(address, source_file, line_nr)

    def by_function(self, name:str):
        """
        Specify a function by name in the binary to filter on.

        Args:
            name (str): The name of the function on which you want to filter.
        
        Short name: ffun
        """
        if self.debugger.get_function_address(name) is None:
            raise DebuggerCommandError(f"Function {name} not found.")
        return FunctionFilter(name)

    def by_stream(self, text:str, stream:StreamType=StreamType.stdout):
        """
        Set a stream filter.

        Args:
            text (str): Text that must be in the stream.
            stream (StreamType): Stream to filter (i.e., stdin/stdout/stderr). Default 'stdout'.
        
        Short name: fstr
        """
        return StdStreamFilter(stream.value, text)
