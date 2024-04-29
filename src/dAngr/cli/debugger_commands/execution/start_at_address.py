import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import DebuggerCommandError, ExecutionError

class StartAtAddressCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("start address", int)]
        self.info = "Start execution at selected entrypoint."

    async def execute(self, address:int):
        self.throw_if_not_initialized()
        await self.send_event(f"Execution started from address {hex(address)}.")
        await self.run()

