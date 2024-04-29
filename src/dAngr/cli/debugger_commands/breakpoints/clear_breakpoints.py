from dAngr.cli.models import Response
from dAngr.exceptions import ExecutionError
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand

class ClearBreakpointsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Remove all breakpoints."
        
    async def execute(self):
        # Find and remove the breakpoint
        self.debugger.breakpoints.clear()
        return Response({}, "All breakpoints cleared.")
