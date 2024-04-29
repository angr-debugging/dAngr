from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.connection import CliConnection


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
        c.send_event = AsyncMock()
        c.send_error = AsyncMock()
        return c

    @pytest.fixture
    async def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("load example")
        conn.send_event = AsyncMock()
        conn.send_error = AsyncMock()
        return dbg

    @pytest.mark.asyncio
    async def test_add_breakpoint(self, dbg, conn):
        r = await dbg.handle("add_breakpoint 0x400566")
        assert r == True
        assert "Breakpoint added and enabled at address 0x400566" == str(conn.send_event.call_args[0][0])
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled")
    
    @pytest.mark.asyncio
    async def test_add_breakpoint2(self, dbg, conn):
        r = await dbg.handle("add_breakpoint 0x400560")
        assert r == True
        assert "Breakpoint added and enabled at address 0x400560" == str(conn.send_event.call_args[0][0])
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400560 in /dangr/tests/example.c line  5 - Enabled")
    
    @pytest.mark.asyncio
    async def test_add_breakpoint_at_line(self, dbg, conn):
        r = await dbg.handle("add_breakpoint_at_line /dangr/tests/example.c 5")
        assert r == True
        assert "Breakpoint added and enabled at address 0x400560" == str(conn.send_event.call_args[0][0])
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400560 in /dangr/tests/example.c line  5 - Enabled")
    
    @pytest.mark.asyncio
    async def test_remove_breakpoint(self, dbg, conn):
        r = await dbg.handle("add_breakpoint 0x400566")
        assert r == True
        r = await dbg.handle("remove_breakpoint 0x400566")
        assert r == True
        assert "Breakpoint removed at 0x400566." == str(conn.send_event.call_args[0][0])
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_remove_non_breakpoint(self, dbg, conn):
        r = await dbg.handle("remove_breakpoint 0x400566")
        assert r == True
        assert "Breakpoint at 0x400566 not found."  == str(conn.send_error.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_enable_breakpoint(self, dbg, conn):
        r = await dbg.handle("add_breakpoint 0x400566")
        assert r == True
        r = await dbg.handle("enable_breakpoint 0x400566")
        assert r == True
        assert "Breakpoint enabled at 0x400566." == str(conn.send_event.call_args[0][0])
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled")
    
    @pytest.mark.asyncio
    async def test_enable_non_breakpoint(self, dbg, conn):
        r = await dbg.handle("enable_breakpoint 0x400566")
        assert r == True
        assert "No breakpoint found at 0x400566." == str(conn.send_error.call_args[0][0])

    @pytest.mark.asyncio
    async def test_disable_breakpoint(self, dbg, conn):
        r = await dbg.handle("add_breakpoint 0x400566")
        assert r == True
        r = await dbg.handle("disable_breakpoint 0x400566")
        assert r == True
        assert "Breakpoint disabled at 0x400566." == str(conn.send_event.call_args[0][0])
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_disable_non_breakpoint(self, dbg, conn):
        r = await dbg.handle("disable_breakpoint 0x400566")
        assert r == True
        assert "No breakpoint found at 0x400566." == str(conn.send_error.call_args[0][0])

    @pytest.mark.asyncio
    async def test_list_breakpoints(self, dbg, conn):
        r = await dbg.handle("add_breakpoint 0x400566")
        assert r == True
        r = await dbg.handle("list_breakpoints")
        assert r == True
        assert "Breakpoints: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled" == str(conn.send_event.call_args[0][0])
       
    @pytest.mark.asyncio
    async def test_list_no_breakpoints(self, dbg, conn):
        r = await dbg.handle("list_breakpoints")
        assert r == True
        assert "No breakpoints set." == str(conn.send_event.call_args[0][0])

    @pytest.mark.asyncio
    async def test_clear_breakpoints(self, dbg, conn):
        r = await dbg.handle("add_breakpoint 0x400566")
        assert r == True
        r = await dbg.handle("clear_breakpoints")
        assert r == True
        assert "All breakpoints cleared." == str(conn.send_event.call_args[0][0])
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")
    
    