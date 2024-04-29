from dAngr.cli.models import Response,Register
from dAngr.exceptions import DebuggerCommandError
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError
from ..base import BaseCommand

class GetRegisterCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("name",str)]
        self.info = "Get a register value."

    async def execute(self, register):
        """Get a register value. Usage: get_register eax"""
        if not self.debugger.is_active():
            raise DebuggerCommandError("Execution not started. First 'load'.")
        
        size = self.debugger.get_register(register)[1]
        value = self.debugger.get_register_value(register, size)
        if value.concrete:
            value = value.concrete_value
        return Response(Register(register,size,value), f"{register} set to {hex(value)}.")

