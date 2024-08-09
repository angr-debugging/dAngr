from dAngr.cli.models import Memory
from ..base import BaseCommand

class GetStringMemoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int,"Address to get memory value from.")]
        self.info = "Get 0 delimited string starting at given memory address and convert it to str."

    async def execute(self, address):
        str_value = self.debugger.get_string_memory(address)
        return Memory(address, str_value, 'str')

