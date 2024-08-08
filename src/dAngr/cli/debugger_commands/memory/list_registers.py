from dAngr.cli.models import Register
from ..base import BaseCommand

class ListRegistersCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List the registers and their current values"

    async def execute(self):
        """List all registers and their current values."""
        regs=[]
        registers = self.debugger.list_registers()
        for reg, (offset, size) in registers.items():
            # Reading register value; size is in bits, need to convert to bytes
            value = self.debugger.get_register_value(reg, size)
            regs.append(Register(reg,size,value))
        
        return  "Registers and their current values:{self}"
    
