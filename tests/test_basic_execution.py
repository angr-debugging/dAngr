from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.connection import CliConnection

import pytest
import os
from unittest.mock import AsyncMock


class TestBasicExecutionCommands:
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
        #reset functions
        conn.send_event = AsyncMock()
        conn.send_error = AsyncMock()
        return dbg

    @pytest.mark.asyncio
    async def test_reload(self, dbg, conn):
        r = await dbg.handle("reload")
        assert r == True
        conn.send_event.assert_called_with("Binary reloaded.")

    @pytest.mark.asyncio
    async def test_continue(self, dbg, conn):
        r = await dbg.handle("continue")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_load_hooks(self, dbg, conn):
        r = await dbg.handle("load_hooks example_hooks.py")
        assert r == True
        conn.send_event.assert_called_with("Hooks 'example_hooks.py' successfully attached.")

    # pause needs further testing
    @pytest.mark.asyncio
    async def test_pause(self, dbg, conn):
        r = await dbg.handle("pause")
        assert r == True
        conn.send_event.assert_called_with("Paused successfully.")

    @pytest.mark.asyncio
    async def test_start_at_address(self, dbg, conn):
        r = await dbg.handle("start_at_address 0x40054d")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_start(self, dbg, conn):
        r = await dbg.handle("start")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_step_into(self, dbg, conn):
        r = await dbg.handle("step")
        assert r == True
        conn.send_event.assert_called_with("Paused at: 0x4003f6")

    @pytest.mark.asyncio
    async def test_step_out(self, dbg, conn):
        r = await dbg.handle("step_out")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")


    @pytest.mark.asyncio
    async def test_step_over(self, dbg, conn):
        r = await dbg.handle("step_over")
        assert r == True
        conn.send_event.assert_called_with("Terminated.")