from dAngr.cli.models import Response,BasicBlock
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class ListPathHistoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Get the address of previously executed basic blocks."

    async def execute(self):
        """List the history of the current execution path."""
        self.throw_if_not_active()
        #TODO: check why it is not working
        paths = self.debugger.list_path_history()
        
        
        return Response({"states":paths}, "Path History: {states}")

