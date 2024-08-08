from dAngr.cli.filters import BreakpointFilter
from dAngr.cli.models import Breakpoint
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand

class EnableBreakpointAtLineCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("source_file", str), ("line_nr",int)]
        self.info = "Enable a breakpoint at the specified source file and line number."

    async def execute(self, sourcefile, line_nr):
        """Enable a breakpoint at the specified source file and line number."""
        for bp in self.debugger.breakpoints:
            if isinstance(bp, BreakpointFilter):
                b:Breakpoint = bp.breakpoint
                if b.source == sourcefile and b.line_nr == line_nr:
                    bp.enabled = True
                    await self.send_info (f"Breakpoint enabled at {b.source}:{b.line_nr}.")
                    return
        raise DebuggerCommandError(f"No breakpoint found at {sourcefile}:{line_nr}.")
    
