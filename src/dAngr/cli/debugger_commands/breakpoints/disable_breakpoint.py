from dAngr.cli.models import Response
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand

class DisableBreakpointCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [ ("address",int)]
        self.info = "Disable a breakpoint at the specified address."

    async def execute(self, address):
        for bp in self.debugger.breakpoints:
            if bp.address == address:
                bp.enabled = False
                return Response(bp, f"Breakpoint disabled at {hex(address)}.")
        raise DebuggerCommandError(f"No breakpoint found at {hex(address)}.")

