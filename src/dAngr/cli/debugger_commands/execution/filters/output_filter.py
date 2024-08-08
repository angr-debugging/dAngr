
import sys
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import StdStreamFilter


class OutputFilterCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("text",str)]
        self.optional_args = [("avoid",bool),("add",bool)]
        self.info = "Filter if outputstream contains text."

    async def execute(self, text:str, avoid:bool=False, add:bool = True): # type: ignore
        #check if the functions exist
        list = self.debugger.exclusions if avoid else self.debugger.breakpoints
        if not add:
            list = [f for f in list if not isinstance(f, StdStreamFilter) or f.value != text]
        else:
            list.append(StdStreamFilter(sys.stdout.fileno(), text))
        await self.send_info(f"Output filter '{text}' {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")