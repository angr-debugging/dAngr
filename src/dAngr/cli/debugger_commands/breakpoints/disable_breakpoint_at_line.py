from dAngr.cli.models import Response
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand

class DisableBreakpointAtLineCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("source_file", str), ("line_nr",int)]
        self.info = "Disable a breakpoint at the specified source file and line number."

    async def execute(self, sourcefile,line_nr):
        """Disable a breakpoint at the specified source file and line number."""
        for bp in self.debugger.breakpoints:
            if bp.source == sourcefile and int(bp.line_nr) == line_nr:
                bp.enabled = False
                return Response(bp, f"Breakpoint disabled at {bp.source}:{bp.line_nr}.")
        raise DebuggerCommandError(f"No breakpoint found at {bp.source}:{bp.line_nr}.".format(bp))
    
