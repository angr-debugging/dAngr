from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class DecompiledFunctionCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("name","str","Name of the function to decompile.")]
        self.info = "Decompiles a function by name."

    async def execute(self, name): # type: ignore
        b = self.debugger.get_decompiled_function(name)
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return f"Function {name}:\n  {b}"

