from dAngr.cli.models import Response
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand

class RemoveBreakpointCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int)]
        self.info = "Remove a breakpoint at a specific address."
        
    async def execute(self, address):
        # Find and remove the breakpoint
        removed = False
        for bp in self.debugger.breakpoints[:]:
            if bp.address == address:
                self.debugger.breakpoints.remove(bp)
                removed = True
                return Response(bp, f"Breakpoint removed at {hex(address)}.")
        if not removed:
            raise DebuggerCommandError(f"Breakpoint at {hex(address)} not found.")

