from dAngr.dAngr_mcp.tools import McpCommand
from dAngr.cli.debugger_commands.breakpoints import BreakpointCommands
from dAngr.cli.debugger_commands.filters import FilterCommands


class BreakpointMCPCommands(McpCommand):
    def __init__(self, debugger, mcp):
        super().__init__(debugger, mcp)
        self.breakpoint_commands = BreakpointCommands(self.debugger)

        

    def break_by_output(self, search_string:str):
        """
        Create a breakpoint that triggers when a matching string is observed in the stdout.
        The breakpoint is triggered when the search string is observed in the stdout.

        Args:
            search_string (str): Substring used to match against stdout stream.

        Returns:
            None
        """

        stream_filter = FilterCommands(self.debugger).by_stream(search_string)
        self.breakpoint_commands.breakpoint(stream_filter)
