from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand

class ExitCommand(BaseCommand):
    def __init__(self, debugger: Debugger):
        super().__init__(debugger)
        self.info = "Exit the debugger."

    async def execute(self):
        self.debugger.stop()

