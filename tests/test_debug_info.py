from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection


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
        c.send_result = AsyncMock()
        c.send_info = AsyncMock()
        c.send_error = AsyncMock()
        return c

    @pytest.fixture
    async def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        assert await dbg.handle("load example")
        assert await dbg.handle("add_breakpoint 0x400566")
        assert await dbg.handle("run")
        return dbg

    # @pytest.mark.asyncio
    # async def test_get_cfg(self, dbg, conn):
    #     assert await dbg.handle("get_cfg")
    #     assert r == True
    #     assert "{\'graph\': \'digraph " in str(conn.send_info.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_get_basicblocks(self, dbg, conn):
        assert await dbg.handle("get_basicblocks")
        assert "Address: 0x40059b" in str(conn.send_result.call_args[0][0])

    @pytest.mark.asyncio
    async def test_get_current_block(self, dbg, conn):
        assert await dbg.handle("get_current_block")
        assert "Current basic block:" in str(conn.send_result.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_active_paths(self, dbg, conn):
        assert await dbg.handle("list_states 'active'")
        assert "[<SimState @ 0x400566>]" == str(conn.send_result.call_args[0][0])    
    @pytest.mark.asyncio
    async def test_list_active_paths2(self, dbg, conn):
        assert await dbg.handle("list_states")
        assert "[<SimState @ 0x400566>]" == str(conn.send_result.call_args[0][0])    
    @pytest.mark.asyncio
    async def test_list_deadended_paths(self, dbg, conn):
        assert await dbg.handle("list_states 'deadended'")
        assert "[]" == str(conn.send_result.call_args[0][0])    

    @pytest.mark.asyncio
    async def test_list_binary_symbols(self, dbg, conn):
        assert await dbg.handle("list_binary_symbols")
        assert "Binary Symbols:" in str(conn.send_result.call_args[0][0])

    @pytest.mark.asyncio
    async def test_list_constraints(self, dbg, conn):
        assert await dbg.handle("list_constraints")
        assert "Constraints:" in str(conn.send_result.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_path_history(self, dbg, conn):
        assert await dbg.handle("list_path_history")
        assert "Path History:" in str(conn.send_result.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_breakpoints(self, dbg, conn):
        assert await dbg.handle("list_breakpoints")
        assert "Breakpoint(s): [0] Address Filter: 0x400566" == str(conn.send_result.call_args[0][0])
    
    