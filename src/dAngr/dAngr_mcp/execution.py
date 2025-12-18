from typing import Any
from dAngr.dAngr_mcp.tools import McpCommand
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.command_line_debugger import ExecutionCommands


class ExecutionMCPCommand(McpCommand):
    def __init__(self, debugger:Debugger, mcp):
        super().__init__(debugger, mcp)
        self.exec_commands = ExecutionCommands(debugger)

    def set_entry_state(self,addr:int|None=None, argv:list[str]=[], other_options: dict[str, Any]  = {}):
        """
        Creates the entry state allowing to set program arguments and optimization options.
        
        Args:
            addr (int|None): The address the state should start at instead of the entry point (usually _start).
            argv: A list of values to use as the program's argv. A 'c program' the first value is the filename. 
            other_options: These kwargs are passed to create the `entry_state` with angr and can be used to set other values such as argc or optimization options.
        """
        other_options['args'] = argv
        #self.debugger.set_entry_state(addr,(), other_options)
        return f"Execution will start {'at address '+hex(addr) if addr else 'at the entry point'}."

        