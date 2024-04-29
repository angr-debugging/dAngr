
import os
from unittest.mock import AsyncMock
import pytest

from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.connection import CliConnection

class TestCommands:
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
    def dbg(self,conn):
        return CommandLineDebugger(conn)

    @pytest.mark.asyncio
    async def test_help(self,dbg, conn):
        r = await dbg.handle("help")
        assert r == True
        conn.send_event.assert_called_once()
        assert "Available commands:" in conn.send_event.call_args[0][0]
        
    @pytest.mark.asyncio
    async def test_help_question_mark(self, dbg, conn):
        r = await dbg.handle("?")
        assert r == True
        conn.send_event.assert_called_once()
        assert "Available commands:" in conn.send_event.call_args[0][0]

    @pytest.mark.asyncio
    async def test_help_command(self, dbg, conn):
        r = await dbg.handle("help continue")
        assert r == True
        conn.send_event.assert_called_once()
        assert "Run until a breakpoint, a fork" in conn.send_event.call_args[0][0]
    @pytest.mark.asyncio
    async def test_command_not_found(self, dbg, conn):
        r = await dbg.handle("not_a_command")
        assert r == True
        conn.send_error.assert_called_once()
        assert "Command 'not_a_command' not found." in str(conn.send_error.call_args[0][0])

    @pytest.mark.asyncio
    async def test_exit(self, dbg, conn):
        r = await dbg.handle("exit")
        assert r == False
        conn.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_exit_with_args(self, dbg, conn):
        r = await dbg.handle("exit args")
        assert r == False
        conn.send_event.assert_not_called()


    @pytest.mark.asyncio
    async def test_load(self, dbg, conn):
        r = await dbg.handle("load example")
        assert r == True
        conn.send_event.assert_called_once_with("Binary 'example' loaded.")
