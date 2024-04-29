from dAngr.cli.models import Response,Memory
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand

class SetMemoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int), ("value",None)]
        self.info = "Set a memory value at a specific address.\nSupported Types: int, str, bytes."

    async def execute(self, address, value):
        if not self.debugger.is_active():
            raise DebuggerCommandError("Execution not started. First 'load'.")
        # Get the byte value
        byte_value = self.debugger.cast_to_bytes(value)
        self.debugger.set_memory(address, byte_value)
        return Response(Memory(address,value,type(value).__name__))

