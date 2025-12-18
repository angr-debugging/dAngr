

from dAngr.MCP.tools import McpCommand
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.command_line_debugger import ExecutionCommands


class ExecutionMCPCommand(McpCommand):
    def __init__(self, debugger:Debugger, mcp):
        super().__init__(debugger, mcp)
        self.exec_commands = ExecutionCommands(debugger)

    def set_entry_state(self,addr:int|None=None, *args, **kwargs):
        """
        Creates the entry state allowing to set program arguments and optimization options.
        
        addr (int|None): The address the state should start at instead of the entry point (usually _start).
        args (tuple): A list of values to use as the program's argv. In a c program the first value of argv is the filename. 
        kwargs (dict): These kwargs are passed to create the `entry_state` with angr. It can also be used to set angr options.
        """

        self.exec_commands.set_entry_state(addr, args, kwargs)
        return f"Execution will start {'at address '+hex(addr) if addr else 'at the entry point'}."

        