from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection


import pytest


import os
from unittest.mock import Mock


class TestDebugBreakpointCommands:
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
    
    
    def test_add_breakpoint(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400566")
        assert "Address 0x400566 added to breakpoints." == str(conn.send_info.call_args[0][0])
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x400566.")
    
    
    def test_add_breakpoint2(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400560")
        assert "Address 0x400560 added to breakpoints." == str(conn.send_info.call_args[0][0])
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x400560.")
    
    
    def test_add_breakpoint_at_line(self, dbg, conn):
        assert dbg.handle("add_breakpoint_at_line '/dangr/tests/example.c' 5")
        conn.send_info.assert_called_with("Address 0x400560 added to breakpoints.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Source Filter: /dangr/tests/example.c:5 (0x400560).")
    
    
    def test_remove_breakpoint(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400566")
        assert "Address 0x400566 added to breakpoints." == str(conn.send_info.call_args[0][0])
        assert dbg.handle("remove_breakpoint 0x400566")
        assert "Address 0x400566 removed from breakpoints." == str(conn.send_info.call_args[0][0])
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")

    
    def test_remove_non_breakpoint(self, dbg, conn):
        assert dbg.handle("remove_breakpoint 0x500")
        assert "Breakpoint at address 0x500 not found."  == str(conn.send_error.call_args[0][0])
    
    
    def test_enable_breakpoint(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400566")
        assert dbg.handle("enable_breakpoint 0")
        assert "Breakpoint filter enabled." == str(conn.send_info.call_args[0][0])
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x400566.")
    
    
    def test_enable_non_breakpoint(self, dbg, conn):
        assert dbg.handle("enable_breakpoint 0", False)
        assert "Index 0 out of range." == str(conn.send_error.call_args[0][0])

    
    def test_disable_breakpoint(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400566")
        assert dbg.handle("disable_breakpoint 0")
        assert "Breakpoint filter disabled." == str(conn.send_info.call_args[0][0])
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")

    
    def test_disable_non_breakpoint(self, dbg, conn):
        assert dbg.handle("disable_breakpoint 0", False)
        assert "Index 0 out of range." == str(conn.send_error.call_args[0][0])

    
    def test_list_breakpoints(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400566")
        assert dbg.handle("list_breakpoints")
        assert "Breakpoint(s): [0] Address Filter: 0x400566" == str(conn.send_result.call_args[0][0])
       
    
    def test_list_no_breakpoints(self, dbg, conn):
        assert dbg.handle("list_breakpoints")
        assert "No breakpoints found." == str(conn.send_info.call_args[0][0])

    
    def test_clear_breakpoints(self, dbg, conn):
        assert dbg.handle("add_breakpoint 0x400566")
        assert dbg.handle("clear_breakpoints")
        assert "All breakpoints cleared." == str(conn.send_info.call_args[0][0])
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")

    def run_to_bp(self, dbg, addr):
        assert dbg.handle(f"add_breakpoint {addr}")
        assert dbg.handle("run")
        assert dbg.current_state.addr == addr

    def test_run_to_bb_bp(self, dbg, conn):
        bb_address = 0x400566
        self.run_to_bp(dbg, bb_address)
        
    def test_run_to_inst_bp(self, dbg, conn):
        addr_in_bb = 0x400570
        self.run_to_bp(dbg, addr_in_bb)



    