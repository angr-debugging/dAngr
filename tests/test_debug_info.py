from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.connection import CliConnection


import pytest


import os
from unittest.mock import AsyncMock


class TestDebugInfoCommands:
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
        await dbg.handle("continue")
        conn.send_event = AsyncMock()
        conn.send_error = AsyncMock()

        return dbg

    # @pytest.mark.asyncio
    # async def test_get_cfg(self, dbg, conn):
    #     r = await dbg.handle("get_cfg")
    #     assert r == True
    #     assert "{\'graph\': \'digraph " in str(conn.send_event.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_get_current_block(self, dbg, conn):
        r = await dbg.handle("get_current_block")
        assert r == True
        assert "Current basic block:" in str(conn.send_event.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_active_paths(self, dbg, conn):
        r = await dbg.handle("list_active_paths")
        assert r == True
        assert "Paths Found: State 0 at 0x400566" == str(conn.send_event.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_binary_symbols(self, dbg, conn):
        r = await dbg.handle("list_binary_symbols")
        assert r == True
        assert "Binary Symbols:" in str(conn.send_event.call_args[0][0])

    @pytest.mark.asyncio
    async def test_list_constraints(self, dbg, conn):
        r = await dbg.handle("list_constraints")
        assert r == True
        assert "Constraints:" in str(conn.send_event.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_path_history(self, dbg, conn):
        r = await dbg.handle("list_path_history")
        assert r == True
        assert "Path History:" in str(conn.send_event.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_breakpoints(self, dbg, conn):
        r = await dbg.handle("list_breakpoints")
        assert r == True
        assert "Breakpoints: Breakpoint at 0x400566" in str(conn.send_event.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_active_paths(self, dbg, conn):
        r = await dbg.handle("list_active_paths")
        assert r == True
        assert "Paths Found: State 0 at 0x400566" in str(conn.send_event.call_args[0][0])
    