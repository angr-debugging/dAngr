from dAngr.cli.models import Response,SymbolicVariable
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class ListConstraintsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List the current path's constraints and symbolic variables."

    async def execute(self):
        """List the current path's constraints and symbolic variables."""
        self.throw_if_not_active()
        
        ctrs = self.debugger.get_constraints()
        return Response({"constraints":ctrs},"Constraints: {constraints}")

