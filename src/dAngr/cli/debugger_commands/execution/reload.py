import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.models import Response
from dAngr.cli.debugger_commands import BaseCommand

class ReloadCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.info = "Reset the simulation manager to the initial state."

    async def execute(self):
        self.debugger.reload()
        await self.send_event(f"Binary reloaded.")


