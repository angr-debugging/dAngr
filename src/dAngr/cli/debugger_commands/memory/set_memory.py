from dAngr.cli.models import Memory
from ..base import BaseCommand

class SetMemoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int), ("value",int|str|bytes)]
        self.info = "Set a memory value at a specific address.\nSupported Types: int, str, bytes."

    async def execute(self, address, value:int|str|bytes):
        # Get the byte value
        byte_value = self.debugger.cast_to_bytes(value)
        self.debugger.set_memory(address, byte_value)
        await self.send_info(f"Memory at {hex(address)}: {byte_value}.")

