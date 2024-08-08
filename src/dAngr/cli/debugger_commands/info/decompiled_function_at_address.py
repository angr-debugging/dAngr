from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class DecompiledFunctionAtAddressCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int)]
        self.info = "Decompiles a function at specified address."

    async def execute(self, address): # type: ignore
        func = self.debugger.get_function_info(address)
        if func is None:
            raise DebuggerCommandError("No function found at this address.")
        b = self.debugger.get_decompiled_function(func.name)
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return f"{b}"

