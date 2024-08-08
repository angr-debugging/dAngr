from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError


class EnableFilterCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("index",int), ("enable",bool)]
        self.optional_args = [("avoid",bool)]
        self.info = "Enable/disable Breakpoint at index. If avoid is set, enable/disable Exclusion filter."
        
    async def execute(self, index:int, enable:bool, avoid:bool=False): # type: ignore
        #if not add:
        list = self.debugger.exclusions if avoid else self.debugger.breakpoints
        if index >= len(list):
            raise DebuggerCommandError(f"Index {index} out of range.")
        list[index].enabled = enable
        await self.send_info(f"{"Exclusion" if avoid else "Breakpoint"} filter {'enabled' if enable else 'disabled'}.")


