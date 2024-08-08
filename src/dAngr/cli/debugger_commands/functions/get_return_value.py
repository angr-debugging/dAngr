from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class GetReturnValueCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Get the return value after running the function."
    
    async def execute(self):
        vals = self.debugger.get_return_values()
        return f"Return value: {",".join([str(v) for v in vals])}"


