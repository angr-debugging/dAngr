import os
from dAngr.cli.models import Response,Breakpoint
from dAngr.exceptions import ExecutionError
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand

class AddBreakpointCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int)]
        self.info = "Set a breakpoint at a given address."

    async def execute(self, address):
        self.throw_if_not_active()
        if any(bp.address == address for bp in self.debugger.breakpoints):
            raise DebuggerCommandError(f"Breakpoint already exists at {hex(address)}")
        #update address with basic block address
        src,line = self.debugger.get_source_info(address)
        if src:
            src = src
        bp = Breakpoint(address, src, line, True)
        self.debugger.breakpoints.append(bp)
        return Response(bp,f"Breakpoint added and enabled at address {hex(address)}")
    
