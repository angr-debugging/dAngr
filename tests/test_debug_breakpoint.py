from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection


import pytest


import os
from unittest.mock import AsyncMock


class TestDebugBreakpointCommands:
    old_dir = os.getcwd()

    def setup_method(self):
        os.chdir(os.path.dirname(__file__))

    def teardown_method(self):
        os.chdir(self.old_dir)



    @pytest.fixture
    def conn(self):
        c = CliConnection()
        c.send_result = AsyncMock()
        c.send_info = AsyncMock()
        c.send_error = AsyncMock()
        return c

    @pytest.fixture
    async def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        assert await dbg.handle("load example")
        return dbg

    @pytest.mark.asyncio
    async def test_add_breakpoint(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400566")
        assert "Breakpoint added and enabled at address 0x400566." == str(conn.send_info.call_args[0][0])
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Break: Breakpoint at 0x400566.")
    
    @pytest.mark.asyncio
    async def test_add_breakpoint2(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400560")
        assert "Breakpoint added and enabled at address 0x400560." == str(conn.send_info.call_args[0][0])
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Break: Breakpoint at 0x400560.")
    
    @pytest.mark.asyncio
    async def test_add_breakpoint_at_line(self, dbg, conn):
        assert await dbg.handle("add_breakpoint_at_line /dangr/tests/example.c 5")
        conn.send_info.assert_called_with("Breakpoint added and enabled at address 0x400560.")
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Break: Breakpoint at 0x400560 in /dangr/tests/example.c line  5.")
    
    @pytest.mark.asyncio
    async def test_remove_breakpoint(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400566")
        assert "Breakpoint added and enabled at address 0x400566." == str(conn.send_info.call_args[0][0])
        assert await dbg.handle("remove_breakpoint 0x400566")
        assert "Breakpoint removed at address 0x400566." == str(conn.send_info.call_args[0][0])
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_remove_non_breakpoint(self, dbg, conn):
        assert await dbg.handle("remove_breakpoint 0x500")
        assert "No breakpoint found at address 0x500."  == str(conn.send_error.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_enable_breakpoint(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400566")
        assert await dbg.handle("enable_breakpoint 0x400566")
        assert "Breakpoint enabled at address 0x400566." == str(conn.send_info.call_args[0][0])
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Break: Breakpoint at 0x400566.")
    
    @pytest.mark.asyncio
    async def test_enable_non_breakpoint(self, dbg, conn):
        assert await dbg.handle("enable_breakpoint 0x400566")
        assert "No breakpoint found at address 0x400566." == str(conn.send_error.call_args[0][0])

    @pytest.mark.asyncio
    async def test_disable_breakpoint(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400566")
        assert await dbg.handle("disable_breakpoint 0x400566")
        assert "Breakpoint disabled at address 0x400566." == str(conn.send_info.call_args[0][0])
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_disable_non_breakpoint(self, dbg, conn):
        assert await dbg.handle("disable_breakpoint 0x400566")
        assert "No breakpoint found at address 0x400566." == str(conn.send_error.call_args[0][0])

    @pytest.mark.asyncio
    async def test_list_breakpoints(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400566")
        assert await dbg.handle("list_breakpoints")
        assert "Breakpoint(s): [0] Breakpoint at 0x400566" == str(conn.send_result.call_args[0][0])
       
    @pytest.mark.asyncio
    async def test_list_no_breakpoints(self, dbg, conn):
        assert await dbg.handle("list_breakpoints")
        assert "No breakpoints set." == str(conn.send_info.call_args[0][0])

    @pytest.mark.asyncio
    async def test_clear_breakpoints(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400566")
        assert await dbg.handle("clear_breakpoints")
        assert "All breakpoints cleared." == str(conn.send_info.call_args[0][0])
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Terminated.")
    
    