from dAngr.cli.models import Response,Register
from dAngr.exceptions import DebuggerCommandError
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError
from ..base import BaseCommand

class SetRegisterCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("name",str), ("value",int)]
        self.info = "Set a register value."

    async def execute(self, register, value):
        """Set a register value. Usage: set register eax 10"""
        if not self.debugger.is_active():
            raise DebuggerCommandError("Execution not started. First 'load'.")
        
        self.debugger.set_register(register, value)
        return Response(Register(register,None,value), f"{register} set to {hex(value)}.")
