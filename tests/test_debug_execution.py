from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.connection import CliConnection


import pytest


import os
from unittest.mock import AsyncMock


class TestDebugExecutionCommands:
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
        await dbg.handle("add_breakpoint 0x400566")
        conn.send_event = AsyncMock()
        conn.send_error = AsyncMock()
        return dbg

    @pytest.mark.asyncio
    async def test_continue(self, dbg, conn):
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled")

    @pytest.mark.asyncio
    async def test_start_at_address(self, dbg, conn):
        r = await dbg.handle("start_at_address 0x40054d")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled")
    # - start
    @pytest.mark.asyncio
    async def test_start(self, dbg, conn):
        r = await dbg.handle("start")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled")

    # - step into
    @pytest.mark.asyncio
    async def test_step_into(self, dbg, conn):
        r = await dbg.handle("step")
        assert r == True
        conn.send_event.assert_called_with("Paused at: 0x4003f6")
    # - step out
    @pytest.mark.asyncio
    async def test_step_out(self, dbg, conn):
        r = await dbg.handle("step_out")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled")

    # - step over
    @pytest.mark.asyncio
    async def test_step_over(self, dbg, conn):
        r = await dbg.handle("step_over")
        assert r == True
        conn.send_event.assert_called_with("Breakpoints hit: Breakpoint at 0x400566 in /dangr/tests/example.c line  5 - Enabled")