from fastmcp import FastMCP
from dAngr.dAngr_mcp.breakpoints import BreakpointMCPCommands
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.command_line_debugger import CommandLineDebugger, DEBUGGER_COMMANDS
from dAngr.dAngr_mcp.execution import ExecutionMCPCommand
from dAngr.dAngr_mcp.mcp_connection import McpConnection
from dAngr.dAngr_mcp.memory import MemoryMCPCommand
from dAngr.dAngr_mcp.symbols import SymbolMCPCommand
from dAngr.dAngr_mcp.tools import dAngr_tools
import inspect
import types

from dAngr.dAngr_mcp.utils import McpUtils

global server_instruction

server_instructions = """The dAngr MCP server exposes a live dAngr debugging session over the Model Context Protocol, allowing external clients to programmatically interact with the debugger. dAngr is a symbolic debugger built on the angr binary analysis framework that combines traditional interactive debugging with symbolic execution to explore multiple execution paths and inspect symbolic program state. The MCP server makes these capabilities accessible as structured tools for breakpoint management, execution control, and state queries.
"""

class dAngrMCP():
    def __init__(self, debugger: CommandLineDebugger, host:str='127.0.0.1', port:int=3000):
        self.debugger = debugger
        if debugger.conn and type(debugger.conn) is CliConnection:
            mcp_con = McpConnection(debugger.conn)
            debugger.conn = mcp_con
        self.mcp = FastMCP("dAngrMCP", instructions=server_instructions)
        self.host = host
        self.port = port
        
        self.init_tools()

    def __recreate_docs(self, cmd_spec):
        doc_str = [cmd_spec.description]
        if cmd_spec.args:
            doc_str.append("\nArgs:")
            for arg in cmd_spec.args:
                if type(arg._dtype) == types.UnionType:
                    type_name = arg._dtype.__str__()
                else:
                    type_name = arg._dtype.__name__
                doc_str.append(f"  {arg.name} ({type_name}): {arg.description}")

        if cmd_spec.example:
            doc_str.append(f"\nExample: {cmd_spec.example}")
        
        return "\n".join(doc_str)
    
    def _check_conn_output(self):
        if type(self.debugger.conn) is not McpConnection:
            return None
        output_str = ""
        if len(self.debugger.conn.output) > 0:
            output_str = "\n".join(self.debugger.conn.output)
            self.debugger.conn.output = []
            return output_str
        
        return None

    def make_tool(self, cmd_spec):
        async def handler(**kwargs):
            context = self.debugger.context
            result = cmd_spec(context, **kwargs)
            return_str = ""
            new_output = self._check_conn_output()
            if new_output:
                return_str = f"Output received: {new_output}\n"
            if result is not None:
                return f"{return_str}{str(result)}"
            elif type(self.debugger.conn) is McpConnection:
                return f"{return_str}{self.debugger.conn.info[-1]}"

            return 'Done'


        handler.__name__ = cmd_spec.name
        handler.__doc__ = self.__recreate_docs(cmd_spec)

        # Build a “real” signature so FastMCP generates a proper schema
        params = []
        ann = {}

        for arg in (cmd_spec.args or []):
            tp = arg._dtype
            ann[arg.name] = tp

            default = inspect._empty

            if hasattr(arg, "default"):
                default = arg.default
            elif getattr(arg, "optional", False) is True:
                default = None

            params.append(
                inspect.Parameter(
                    arg.name,
                    kind=inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=tp,
                )
            )

        handler.__annotations__ = ann
        handler.__signature__ = inspect.Signature(parameters=params)

        return handler



    def init_tools(self):
        BreakpointMCPCommands(self.debugger, self.mcp)
        ExecutionMCPCommand(self.debugger, self.mcp)
        McpUtils(self.debugger, self.mcp)
        SymbolMCPCommand(self.debugger, self.mcp)
        MemoryMCPCommand(self.debugger, self.mcp)

        for cmd_name, cmd_spec in DEBUGGER_COMMANDS.items():
            try:
                if cmd_name in dAngr_tools:
                    self.mcp.tool()(self.make_tool(cmd_spec))
            except Exception:
                print(f"Could not create a tool_call for the command: {cmd_name}")

    def run(self):
        self.mcp.run(transport="streamable-http", host=self.host, port=self.port, log_level='CRITICAL')


if __name__ == "__main__":
    _debugger = CommandLineDebugger(CliConnection())
    mcp_server = dAngrMCP(_debugger)
    mcp_server.run()
