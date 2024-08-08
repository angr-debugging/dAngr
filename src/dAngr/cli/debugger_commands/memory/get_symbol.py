from dAngr.cli.models import Memory
from dAngr.utils.utils import Type
from ..base import BaseCommand


class GetSymbolCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("name",str)]
        self.optional_args = [("type",Type)]
        self.info = "Get a symbol with a given name."


    async def execute(self, name, type:Type = Type.BYTES):
        val = self.debugger.get_symbol_value(name)
        if type == Type.BYTES:
            num_bytes = (val.bit_length() + 7) // 8 
            val = val.to_bytes(num_bytes, byteorder='big') 
        elif type == Type.INT:
            val = int(val)
        elif type == Type.DOUBLE:
            val = float(val)
        elif type == Type.BOOL:
            val = bool(val)
        elif type == Type.STR:
            num_bytes = (val.bit_length() + 7) // 8 
            val = val.to_bytes(num_bytes, byteorder='big') 
            try:
                val = val.decode('utf-8')
            except UnicodeDecodeError:
                await self.send_error(f"Symbol {name} is not a valid string.")
        elif type == Type.HEX:
            val = '{:x}'.format(val)
        else:
            raise ValueError(f"Invalid type {type}.")
        await self.send_result(f"Symbol {name} is {val}.")
            
