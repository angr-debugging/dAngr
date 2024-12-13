import os
import pytest

from unittest.mock import Mock

from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.command_line_debugger import CommandLineDebugger, dAngrExecutionContext
from dAngr.cli.grammar.parser import parse_input
from dAngr.cli.grammar.script import Script


class TestGenericCommandExecution:
    old_dir = os.getcwd()

    def setup_method(self):
        os.chdir(os.path.dirname(__file__))

    def teardown_method(self):
        os.chdir(self.old_dir)


    
    @pytest.fixture
    def conn(self):
        c = CliConnection()
        c.send_output = Mock()
        return c

    @pytest.fixture
    def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        return dbg

    def test_python_command(self,capsys,dbg):
        input = "!print('x')"
        result = parse_input(input, dbg)
        
        assert isinstance(result, Script)
        ctx = dAngrExecutionContext(dbg,{})
        r = result(ctx)
        assert r == None
        assert str(dbg.conn.send_output.call_args[0][0])  == "x\n"
    
    def test_test_claripy(self,capsys,dbg):
        r = dbg.handle("load 'example'")
        assert r == True
        r = dbg.handle("set_blank_state")
        r = dbg.handle("add_symbol a 1")
        r = dbg.handle("add_symbol b 1")
        r = dbg.handle("add_constraint &sym.a + &sym.b == b'ab'")
        assert r == True, "add_constraints failed"

