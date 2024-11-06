from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection


import pytest


import os
from unittest.mock import Mock


class TestDebugExecutionCommands:
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
        dbg = CommandLineDebugger(conn)
        assert dbg.handle("load example")
        return dbg

    
    def test_continue(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400611")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x400611.")

    
    def test_set_start_address(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400611")
        conn.send_info.assert_called_with("Address 0x400611 added to breakpoints.")
        assert dbg.handle("add_breakpoint 0x4005de")
        assert dbg.handle("set_entry_state 0x40054d")
        conn.send_info.assert_called_with("Execution will start at address 0x40054d.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4005de.") # should not stop at 0x400611
    # - start
    
    def test_start(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400611")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x400611.")

    # - step into
    
    def test_step_into(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x40062a")
        assert dbg.handle("run")
        assert dbg.handle("step")
        conn.send_info.assert_called_with("Stepped to: 0x40054d.")

    # - step out
    
    def test_step_out(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x40054d")
        assert dbg.handle("run")
        assert dbg.handle("step_out")
        conn.send_info.assert_called_with("Stepped to: 0x40062f.")

    # - step over
    
    def test_step_over(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x40062a")
        assert dbg.handle("run")
        assert dbg.handle("step_over")
        conn.send_info.assert_called_with("Stepped to: 0x40062f.")