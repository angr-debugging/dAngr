from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection


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
        c.send_result = AsyncMock()
        c.send_info = AsyncMock()
        c.send_error = AsyncMock()
        return c

    @pytest.fixture
    async def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        assert await dbg.handle("load example")
        conn.send_info = AsyncMock()
        conn.send_error = AsyncMock()
        return dbg

    @pytest.mark.asyncio
    async def test_continue(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400611")
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Break: Breakpoint at 0x400611.")

    @pytest.mark.asyncio
    async def test_set_start_address(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400611")
        conn.send_info.assert_called_with("Breakpoint added and enabled at address 0x400611.")
        assert await dbg.handle("add_breakpoint 0x4005de")
        assert await dbg.handle("set_start_address 0x40054d")
        conn.send_info.assert_called_with("Execution will start at address 0x40054d.")
        assert await dbg.handle("start")
        conn.send_info.assert_called_with("Break: Breakpoint at 0x4005de.") # should not stop at 0x400611
    # - start
    @pytest.mark.asyncio
    async def test_start(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x400611")
        assert await dbg.handle("start")
        conn.send_info.assert_called_with("Break: Breakpoint at 0x400611.")

    # - step into
    @pytest.mark.asyncio
    async def test_step_into(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x40062a")
        assert await dbg.handle("start")
        assert await dbg.handle("step")
        conn.send_info.assert_called_with("Stepped to: 0x40054d.")

    # - step out
    @pytest.mark.asyncio
    async def test_step_out(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x40054d")
        assert await dbg.handle("start")
        assert await dbg.handle("step_out")
        conn.send_info.assert_called_with("Stepped to: 0x40062f.")

    # - step over
    @pytest.mark.asyncio
    async def test_step_over(self, dbg, conn):
        assert await dbg.handle("add_breakpoint 0x40062a")
        assert await dbg.handle("start")
        assert await dbg.handle("step_over")
        conn.send_info.assert_called_with("Stepped to: 0x40062f.")