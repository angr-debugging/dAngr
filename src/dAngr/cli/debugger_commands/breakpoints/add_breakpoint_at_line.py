import os
from dAngr.cli.models import Response,Breakpoint
from dAngr.exceptions import ExecutionError
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand


class AddBreakpointAtLineCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("source_file", str), ("line_nr",int)]
        self.info = "Set a breakpoint at an address corresponding to the 'filename' and 'line number' in the source code file\n Requires debug sumbols available in the binary."

    async def execute(self, sourcefile, line_nr):
        self.throw_if_not_active()
        address = self.debugger.find_address(sourcefile, line_nr)
        if any(bp.address == address for bp in self.debugger.breakpoints):
            raise DebuggerCommandError(f"Breakpoint already exists at {hex(address)}")
        bp = Breakpoint(address, sourcefile, line_nr, True)
        self.debugger.breakpoints.append(bp)
        return Response(bp,f"Breakpoint added and enabled at address {hex(address)}")
    
