from dAngr.cli.filters import BreakpointFilter
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand

class RemoveBreakpointAtLineCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("source_file", str,"File path of the source file"), ("line_nr",int,"Line number in the source file")]
        self.info = "Remove a breakpoint at an address corresponding to the filename and line number of the source code\n Requires debug sumbols available in the binary."

    async def execute(self, sourcefile:str, line_nr:int): 
        # Find and remove the breakpoint
        for bp in self.debugger.breakpoints:
            if isinstance(bp, BreakpointFilter):
                b = bp.breakpoint
                if b.source == sourcefile and b.line_nr == line_nr:
                    self.debugger.breakpoints.remove(bp)
                    await self.send_info(  f"Breakpoint removed at {b.source}:{b.line_nr}.")
                    return
        raise DebuggerCommandError(f"No breakpoint found at {sourcefile}:{line_nr}.")
