from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection

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
        c.send_result = AsyncMock()
        c.send_info = AsyncMock()
        c.send_error = AsyncMock()
        return c

    @pytest.fixture
    async def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("load example")
        #reset functions
        conn.send_info = AsyncMock()
        conn.send_error = AsyncMock()
        return dbg

    @pytest.mark.asyncio
    async def test_reset(self, dbg, conn):
        assert await dbg.handle("reset_state")
        conn.send_info.assert_called_with("State reset.")

    @pytest.mark.asyncio
    async def test_continue(self, dbg, conn):
        assert await dbg.handle("continue")
        conn.send_info.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_load_hooks(self, dbg, conn):
        assert await dbg.handle("load_hooks example_hooks.py")
        conn.send_info.assert_called_with("Hooks 'example_hooks.py' successfully attached.")

    # pause needs further testing
    @pytest.mark.asyncio
    async def test_pause(self, dbg, conn):
        assert await dbg.handle("pause")
        conn.send_info.assert_called_with("Paused successfully.")

    @pytest.mark.asyncio
    async def test_set_start_address(self, dbg, conn):
        assert await dbg.handle("set_start_address 0x40054d")
        conn.send_info.assert_called_with("Execution will start at address 0x40054d.")
        assert await dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_start(self, dbg, conn):
        assert await dbg.handle("run")
        conn.send_info.assert_called_with("Terminated.")

    @pytest.mark.asyncio
    async def test_step_into(self, dbg, conn):
        assert await dbg.handle("step")
        conn.send_info.assert_called_with("Stepped to: 0x4003f6.")

    @pytest.mark.asyncio
    async def test_step_out(self, dbg, conn):
        assert await dbg.handle("step_out")
        conn.send_info.assert_called_with("Terminated.")


    @pytest.mark.asyncio
    async def test_step_over(self, dbg, conn):
        assert await dbg.handle("step_over")
        conn.send_info.assert_called_with("Terminated.")
    
    @pytest.mark.asyncio
    async def test_select_path(self, dbg, conn):
        assert await dbg.handle("select_path 0")
        assert 'Path 0 selected: 0x4003e0' in str(conn.send_info.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_exclude_function(self, dbg, conn):
        assert await dbg.handle("filter_at_function main True")
        conn.send_info.assert_called_with("Function main added to exclusions.")
        assert await dbg.handle("filter_at_function main True False")
        conn.send_info.assert_called_with("Function main removed from exclusions.")
    
    @pytest.mark.asyncio
    async def test_exclude_address(self, dbg, conn):
        assert await dbg.handle("filter 0x40054d True")
        conn.send_info.assert_called_with("Address 0x40054d added to exclusions.")
        assert await dbg.handle("filter 0x40054d True False")
        conn.send_info.assert_called_with("Address 0x40054d removed from exclusions.")

    @pytest.mark.asyncio
    async def test_list_exclusions(self, dbg, conn):
        assert await dbg.handle("filter_list True")
        conn.send_info.assert_called_with("No exclusions set.")
        assert await dbg.handle("filter 0x40054d True")
        assert await dbg.handle("filter_list True")
        conn.send_result.assert_called_with("Exclusion(s): [0] Address Filter: 0x40054d")