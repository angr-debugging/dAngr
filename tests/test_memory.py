from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.connection import CliConnection


import pytest


import os
from unittest.mock import AsyncMock


class TestMemoryCommands:
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
        await dbg.handle("set_function_prototype int processMessage(char*, int, char**)")
        await dbg.handle("set_function_call processMessage('abc',2,b'0000000000')")

        conn.send_event = AsyncMock()
        conn.send_error = AsyncMock()

        return dbg

    @pytest.mark.asyncio
    async def test_get_memory(self, dbg, conn):
        r = await dbg.handle("get_memory 0x1000 3")
        assert r == True
        assert "Memory at 0x1000: b'abc' (bytes)" == str(conn.send_event.call_args[0][0])
    
    # @pytest.mark.asyncio
    # async def test_get_int_memory(self, dbg, conn):
    #     r = await dbg.handle("get_int_memory 0x3000 3")
    #     assert r == True
    #     assert "Memory at 0x2000: 0 (int)" == str(conn.send_event.call_args[0][0])
    @pytest.mark.asyncio
    async def test_get_string_memory(self, dbg, conn):
        r = await dbg.handle("get_string_memory 0x1000")
        assert r == True
        assert "Memory at 0x1000: abc (str)" == str(conn.send_event.call_args[0][0])
    @pytest.mark.asyncio
    async def test_get_register(self, dbg, conn):
        r = await dbg.handle("get_register ip")
        assert r == True
        assert "ip set to 0x4d." == str(conn.send_event.call_args[0][0])

    @pytest.mark.asyncio
    async def test_get_register_invalid(self, dbg, conn):
        r = await dbg.handle("get_register invalid")
        assert r == True
        assert "Register 'invalid' not found." == str(conn.send_error.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_get_register_invalid_args(self, dbg, conn):
        r = await dbg.handle("get_register")
        assert r == True
        assert "Invalid input format. Expected arguments: name" == str(conn.send_error.call_args[0][0])
    
    @pytest.mark.asyncio
    async def test_list_registers(self, dbg, conn):
        r = await dbg.handle("list_registers")
        assert r == True
        assert "Registers and their current values:" in str(conn.send_event.call_args[0][0])

    @pytest.mark.asyncio
    async def test_set_register(self, dbg, conn):
        r = await dbg.handle("set_register ip 0x4e")
        assert r == True
        assert "ip set to 0x4e." == str(conn.send_event.call_args[0][0])

    @pytest.mark.asyncio
    async def test_set_memory(self, dbg, conn):
        r = await dbg.handle("set_memory 0x1000 0x61")
        assert r == True
        assert "Memory at 0x1000: 97 (int)" == str(conn.send_event.call_args[0][0])

    @pytest.mark.asyncio
    async def test_zero_fill_memory(self, dbg, conn):
        r = await dbg.handle("zero_fill")
        assert r == True
        assert "Zero fill enabled." == str(conn.send_event.call_args[0][0])

        r = await dbg.handle("zero_fill False")
        assert r == True
        assert "Zero fill disabled." == str(conn.send_event.call_args[0][0])
            
