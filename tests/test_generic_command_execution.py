import pytest

from unittest.mock import AsyncMock

from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.command_line_debugger import CommandLineDebugger, dAngrExecutionContext
from dAngr.cli.grammar.control_flow import ForLoop, IfThenElse
from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.cli.grammar.parser import lex_input, parse_input
from dAngr.cli.grammar.expressions import BashCommand, Comparison, Dictionary, Expression, Iterable, Listing, Literal, DangrCommand, PythonCommand, Range, VariableRef
from dAngr.cli.grammar.script import Body, Script
from dAngr.cli.grammar.statements import Assignment
from dAngr.exceptions import ParseError


class TestGenericCommandExecution:

    def setup_method(self):
        pass
    def teardown_method(self):
        pass
    
    @pytest.fixture
    def conn(self):
        c = CliConnection()
        c.send_output = AsyncMock()
        return c

    @pytest.fixture
    async def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        return dbg

    async def test_python_command(self,capsys,dbg):
        input = "!print('x')"
        result = parse_input(input)
        
        assert isinstance(result, Script)
        ctx = dAngrExecutionContext(dbg,{})
        r = await result(ctx)
        assert r == None
        assert str(dbg.conn.send_output.call_args[0][0])  == "x\n"
