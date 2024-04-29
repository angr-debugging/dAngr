from dAngr.cli.models import Response
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ..base import BaseCommand

class RemoveBreakpointAtLineCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("source_file", str), ("line_nr",int)]
        self.info = "Remove a breakpoint at an address corresponding to the filename and line number of the source code\n Requires debug sumbols available in the binary."

    async def execute(self, args):
        sourcefile, line_nr = args.split()
        line_nr = int(line_nr)
        # Find and remove the breakpoint
        removed = False
        for bp in self.debugger.breakpoints[:]:
            if bp.source == sourcefile and int(bp.line_nr) == line_nr:
                self.debugger.breakpoints.remove(bp)
                removed = True
                return Response(bp, f"Breakpoint removed at {bp.source}:{bp.line_nr}.")
        if not removed:
            raise DebuggerCommandError(f"Breakpoint not at {bp.source}:{bp.line_nr} found.")
