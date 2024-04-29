from dAngr.cli.models import Response,BasicBlock
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class GetCurrentBlockCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Show the assembly for the current basic block."
    async def execute(self):
        self.throw_if_not_active()
        b = self.debugger.get_current_basic_block()
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return Response(b, "Current basic block: {self}")

