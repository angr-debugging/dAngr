
import os
from unittest.mock import Mock
import pytest

from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.exceptions import CommandError, DebuggerCommandError
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError

class TestCommands:
    old_dir = os.getcwd()
    
    def setup_method(self):
        os.chdir(os.path.dirname(__file__))

    def teardown_method(self):
        os.chdir(self.old_dir)
        
    
    @pytest.fixture
    def conn(self):
        c = CliConnection()
        c.send_result = Mock()
        c.send_info = Mock()
        c.send_error = Mock()
        return c
    
    @pytest.fixture
    def dbg(self,conn):
        return CommandLineDebugger(conn)

    
    def test_help(self,dbg, conn):
        assert dbg.handle("help")
        conn.send_result.assert_called_once()
        assert "Available commands:" in conn.send_result.call_args[0][0]
        
    
    def test_help_question_mark(self, dbg, conn):
        assert dbg.handle("?")
        conn.send_result.assert_called_once()
        assert "Available commands:" in conn.send_result.call_args[0][0]

    
    def test_help_command(self, dbg, conn):
        assert dbg.handle("help run")
        conn.send_result.assert_called_once()
        assert "Run until a breakpoint or" in conn.send_result.call_args[0][0]
    
    def test_command_not_found(self, dbg, conn):
        assert dbg.handle("not_a_command", False)
        conn.send_error.assert_called_once()
        assert "Unknown command:" in str(conn.send_error.call_args[0][0])

    
    def test_exit(self, dbg, conn):
        assert not dbg.handle("exit")
        conn.send_info.assert_not_called()

    
    def test_exit_with_args(self, dbg, conn):
        assert dbg.handle("exit args", False)
        conn.send_info.assert_not_called()
        conn.send_error.assert_called_once_with(InvalidArgumentError('Too many arguments. Expected 0 but got 1'))


    
    def test_load(self, dbg, conn):
        assert dbg.handle("load example")
        conn.send_info.assert_called_once_with("Binary 'example' loaded.")

    
    def test_load_invalid(self, dbg, conn):
        assert dbg.handle("load invalid", False)
        conn.send_error.assert_called_once_with(DebuggerCommandError("Failed to load binary: File 'invalid' not found."))
    
    
    def test_load_args(self, dbg, conn):
        assert dbg.handle("load example args", False)
        conn.send_error.assert_called_once_with(DebuggerCommandError('Unknown variable: args'))
    
    
    def test_variable(self, dbg, conn):
        assert dbg.handle("test = 1")
        assert dbg.handle("&vars.test")
        conn.send_result.assert_called_once()
        assert 1 == conn.send_result.call_args[0][0]