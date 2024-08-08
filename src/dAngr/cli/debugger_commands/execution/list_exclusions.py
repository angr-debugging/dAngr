from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError


class ListExclusionsCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.info = "Ignore paths containing address."
        
    async def execute(self ): # type: ignore
        if not self.debugger.exclusions:
            await self.send_info("No exclusions.")
            return []
        else:
            return f"Exclusions: {"\n".join([str(f) for f  in self.debugger.exclusions])}"

