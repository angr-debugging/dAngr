import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand

class ResetStateCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.info = "Reset the simulation manager to the initial state."
        self.short_cmd_name = "r"

    async def execute(self):
        self.debugger.reset_state()
        entry_point = self.debugger.entry_point
        if entry_point is None:
            await self.send_info("State reset.")
        else:
            s = f"address {hex(entry_point)}" if isinstance(entry_point, int) else f"to function {entry_point[0]} with arguments {[str(a) for a in entry_point[3]]}"
            await self.send_info(f"State reset at entry point {s}.")


