from typing import cast
from dAngr.cli.filters import BreakpointFilter
from dAngr.cli.models import Breakpoint
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand

class DisableBreakpointAtLineCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("source_file", str,"File path of the source file"), ("line_nr",int,"Line number in the source file")]
        self.info = "Disable a breakpoint at the specified source file and line number."

    async def execute(self, sourcefile,line_nr):
        """Disable a breakpoint at the specified source file and line number."""
        for bp in self.debugger.breakpoints:
            #if breakpoint filter
            if isinstance(bp, BreakpointFilter):
                b:Breakpoint = bp.breakpoint
                if b.source == sourcefile and int(b.line_nr) == line_nr: # type: ignore
                    b.enabled = False
                    await self.send_info( f"Breakpoint disabled at {b.source}:{b.line_nr}.")
                    return
        raise DebuggerCommandError(f"No breakpoint found at {sourcefile}:{line_nr}.")
    
