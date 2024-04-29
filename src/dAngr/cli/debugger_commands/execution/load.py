import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.models import Response
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import DebuggerCommandError

class LoadCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("binary path", str)]
        self.info = "Setup the simulation manager with the initial state."

    async def execute(self, binary_path:str):
        try:
            self.debugger.init(binary_path)
        except Exception as e:
            raise DebuggerCommandError(f"Failed to load binary: {e}")
        f = os.path.basename(binary_path)
        await self.send_event(f"Binary '{f}' loaded.")


