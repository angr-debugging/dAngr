from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection

import pytest
import os
from unittest.mock import Mock


class TestBasicExecutionCommands:
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
        dbg.handle("load 'example'")
        return dbg

    
    def test_reset(self, dbg, conn):
        assert dbg.handle("reset_state")
        conn.send_info.assert_called_with("State reset.")

    
    def test_continue(self, dbg, conn):
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")

    
    def test_load_hooks(self, dbg, conn):
        assert dbg.handle("load_hooks 'example_hooks.py'")
        conn.send_info.assert_called_with("Hooks 'example_hooks.py' successfully attached.")

    # pause needs further testing
    
    def test_pause(self, dbg, conn):
        assert dbg.handle("pause")
        conn.send_info.assert_called_with("Paused successfully.")

    
    def test_set_start_address(self, dbg, conn):
        assert dbg.handle("set_entry_state 0x40054d")
        conn.send_info.assert_called_with("Execution will start at address 0x40054d.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")
    
    
    def test_option_enum(self,dbg, conn):
        input = "set_entry_state add_options=[options.LAZY_SOLVES]"
        assert dbg.handle(input)
        conn.send_info.assert_called_with("Execution will start at specified entry point.")

    
    def test_start(self, dbg, conn):
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")

    
    def test_step_into(self, dbg, conn):
        assert dbg.handle("step")
        conn.send_info.assert_called_with("Stepped to: 0x4003f6.")

    
    def test_step_back(self, dbg, conn):
        assert dbg.handle("to_hex &state.addr")
        conn.send_result.assert_called_with("0x4003e0", True)
        assert dbg.handle("step")
        conn.send_info.assert_called_with("Stepped to: 0x4003f6.")
        assert dbg.handle("back")
        conn.send_info.assert_called_with("Stepped back to: 0x4003e0.")
        assert dbg.handle("step")
        conn.send_info.assert_called_with("Stepped to: 0x4003f6.")

    
    def test_step_out(self, dbg, conn):
        assert dbg.handle("step_out")
        conn.send_info.assert_called_with("Terminated.")


    
    def test_step_over(self, dbg, conn):
        assert dbg.handle("step_over")
        conn.send_info.assert_called_with("Terminated.")
    
    
    def test_select_path(self, dbg, conn):
        assert dbg.handle("select_state 0")
        assert 'Path 0 selected: 0x4003e0' in str(conn.send_info.call_args[0][0])
    
    
    def test_exclude_function(self, dbg, conn):
        dbg.handle("f = by_function 'main'")
        dbg.handle("exclude f")
        conn.send_info.assert_called_with("Function Filter: main added to exclusions.")
        assert dbg.handle("remove_exclusion_filter 0")
        conn.send_info.assert_called_with("Function Filter: main removed from exclusions.")
    
    
    def test_exclude_address(self, dbg, conn):
        assert dbg.handle("f = by_address 0x40054d")
        dbg.handle("exclude f")
        conn.send_info.assert_called_with("Address Filter: 0x40054d added to exclusions.")
        assert dbg.handle("f = by_address 0x40054d")
        dbg.handle("remove_exclusion_filter 0")
        conn.send_info.assert_called_with("Address Filter: 0x40054d removed from exclusions.")

    
    def test_list_exclusions(self, dbg, conn):
        assert dbg.handle("list_exclusions")
        conn.send_info.assert_called_with("No exclusions found.")
        dbg.handle("f = by_address 0x40054d")
        dbg.handle("exclude f")
        assert dbg.handle("list_exclusions")
        conn.send_result.assert_called_with("Exclusion(s): [0] Address Filter: 0x40054d", True)