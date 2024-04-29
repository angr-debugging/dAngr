from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import DebuggerCommandError, ExecutionError


class ContinueCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.info = "Run until a breakpoint, a fork (if not fully concrete), or until execution completed."
        
    async def execute(self):
        self.throw_if_not_active()
        await self.run()


