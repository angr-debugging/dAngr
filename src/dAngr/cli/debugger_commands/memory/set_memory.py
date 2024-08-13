from dAngr.cli.models import Memory
from ..base import BaseCommand

class SetMemoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int,"Address in the memory"), ("value",int|str|bytes,"Value to set at the address.")]
        self.info = "Set a memory value at a specific address.\nSupported Types: int, str, bytes."

    async def execute(self, address:int, value:int|str|bytes):
        # Get the byte value
        if isinstance(value, str):
            v = self.debugger.get_new_symbol_object(value)
            self.debugger.set_memory(address,v)
        else:
            byte_value = self.debugger.cast_to_bytes(value)
            self.debugger.set_memory(address, byte_value)
            await self.send_info(f"Memory at {hex(address)}: {byte_value}.")
