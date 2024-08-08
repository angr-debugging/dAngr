from  dAngr.cli.models import Memory
from ..base import BaseCommand

class GetMemoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int),("size",int)]
        self.info = "Get memory value of lengt size at a specific address as a byte array."


    async def execute(self, address,size):
        byte_value = self.debugger.get_memory(address, size)
        if byte_value.concrete:
            byte_value = self.debugger.cast_to(byte_value, cast_to=bytes)
        
        return Memory(address, byte_value, "bytes")
