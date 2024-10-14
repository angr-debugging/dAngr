
import os
from unittest.mock import AsyncMock
import pytest

from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError

class TestCommands:
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
    def dbg(self,conn):
        return CommandLineDebugger(conn)

    @pytest.mark.asyncio
    async def test_help(self,dbg, conn):
        assert await dbg.handle("help")
        conn.send_result.assert_called_once()
        assert "Available commands:" in conn.send_result.call_args[0][0]
        
    @pytest.mark.asyncio
    async def test_help_question_mark(self, dbg, conn):
        assert await dbg.handle("?")
        conn.send_result.assert_called_once()
        assert "Available commands:" in conn.send_result.call_args[0][0]

    @pytest.mark.asyncio
    async def test_help_command(self, dbg, conn):
        assert await dbg.handle("help continue")
        conn.send_result.assert_called_once()
        assert "Run until a breakpoint or" in conn.send_result.call_args[0][0]
    @pytest.mark.asyncio
    async def test_command_not_found(self, dbg, conn):
        assert await dbg.handle("not_a_command")
        conn.send_error.assert_called_once()
        assert "Unknown command:" in str(conn.send_error.call_args[0][0])

    @pytest.mark.asyncio
    async def test_exit(self, dbg, conn):
        assert not await dbg.handle("exit")
        conn.send_info.assert_not_called()

    @pytest.mark.asyncio
    async def test_exit_with_args(self, dbg, conn):
        assert await dbg.handle("exit args")
        conn.send_info.assert_not_called()
        conn.send_error.assert_called_once_with(InvalidArgumentError('Too many arguments. Expected 0 but got 1'))


    @pytest.mark.asyncio
    async def test_load(self, dbg, conn):
        assert await dbg.handle("load example")
        conn.send_info.assert_called_once_with("Binary 'example' loaded.")
