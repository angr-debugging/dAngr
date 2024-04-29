from dAngr.cli.models import Response
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class GetReturnValueCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Get the return value after running the function."
    
    async def execute(self):
        self.throw_if_not_finished()
        vals = self.debugger.get_return_values()
        return Response({"return_value":",".join([str(v) for v in vals])}, "Return value: {return_value}")


