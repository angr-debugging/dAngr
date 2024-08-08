import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import DebuggerCommandError, ExecutionError

class SetStartAddressCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("start address", int)]
        self.info = "Start execution at selected entrypoint."

    async def execute(self, address:int):
        self.debugger.set_start_address(address)
        await self.send_info(f"Execution will start at address {hex(address)}.")
