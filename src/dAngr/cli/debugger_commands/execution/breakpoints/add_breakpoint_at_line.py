import os
from typing import cast
from dAngr.cli.filters import BreakpointFilter
from dAngr.cli.models import Breakpoint
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand


class AddBreakpointAtLineCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("source_file", str), ("line_nr",int)]
        self.info = "Set a breakpoint at an address corresponding to the 'filename' and 'line number' in the source code file\n Requires debug symbols available in the binary."

    async def execute(self, sourcefile, line_nr): # type: ignore
        address = self.debugger.find_address(sourcefile, line_nr)
        if address is None:
            raise DebuggerCommandError(f"No address found for {sourcefile}:{line_nr}.")
        if any(bp.address == address for bp in self.debugger.breakpoints if isinstance(bp, BreakpointFilter)):
            raise DebuggerCommandError(f"Breakpoint already exists at {hex(address)}.")
        bp = BreakpointFilter(address, sourcefile, line_nr, True)
        self.debugger.breakpoints.append(bp)
        await self.send_info(f"Breakpoint added and enabled at address {hex(address)}.")
    
