from dAngr.cli.models import Memory, Response
from dAngr.exceptions import DebuggerCommandError
from ..base import BaseCommand

class GetIntMemoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int)]
        self.info = "Get memory value as integer."

    async def execute(self, address):
        if not self.debugger.is_active():
            raise DebuggerCommandError("Execution not started. First 'load'.")
        byte_value = self.debugger.get_int_memory(address)
        if byte_value.concrete:
            byte_value = self.debugger.cast_to(byte_value, cast_to=int)
        return Response(Memory(address, byte_value, "int"))
    
