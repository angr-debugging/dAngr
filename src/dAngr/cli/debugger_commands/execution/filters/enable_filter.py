from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError


class EnableFilterCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("index",int,"Index of the filter found using list_filters"), ("enable",bool, "True to enable, False to disable")]
        self.optional_args = [("exclusion",bool, "Whether it is an exclusion or breakpoint filter. Default is breakpoint.")]
        self.info = "Enable/disable Breakpoint at index. If exclusion is set, enable/disable Exclusion filter."
        
    async def execute(self, index:int, enable:bool, exclusion:bool=False): # type: ignore
        #if not add:
        list = self.debugger.exclusions if exclusion else self.debugger.breakpoints
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        list[index].enabled = enable
        await self.send_info(f"{'Exclusion' if exclusion else 'Breakpoint'} filter {'enabled' if enable else 'disabled'}.")


