from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import ExecutionError

class PauseCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.info = "Pause debugging."
    
    async def execute(self):
        await self.debugger.pause()
        await self.send_info("Paused successfully.")

