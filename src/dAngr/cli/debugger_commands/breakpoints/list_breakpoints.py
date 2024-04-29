from dAngr.cli.models import Response
from..base import BaseCommand

class ListBreakpointsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List all breakpoints."

    async def execute(self):
        if not self.debugger.breakpoints:
            return Response({}, "No breakpoints set.")
        return Response( self.debugger.breakpoints, "Breakpoints: {self}")

