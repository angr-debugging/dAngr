from dAngr.cli.models import Register
from dAngr.exceptions import DebuggerCommandError

from ..base import BaseCommand

class SetRegisterCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("name",str,"Name of the register"), ("value",int|str,"Value to set at the register.")]
        self.info = "Set a register value. Usage: set register eax 10.\n if the value is a string, the symbol will be looked up and assigned to the registry."

    async def execute(self, register:str, value:int|str):

        if isinstance(value, str):
            v = self.debugger.get_new_symbol_object(value)
            self.debugger.set_register(register, v)
            await self.send_info( f"{register} set to symbol {value}.")
        else:
            self.debugger.set_register(register, value)
            await self.send_info( f"{register} set to {hex(value)}.")
