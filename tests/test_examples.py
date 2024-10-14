
import os
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from prompt_toolkit import PromptSession
import pytest

from dAngr.cli.command_line_debugger import DEBUGGER_COMMANDS, CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.server import Server
from tests.LoggingAsyncMock import LoggingAsyncMock



class TestExamples:


    @pytest.fixture
    def conn(self):
        c = CliConnection()
        c.send_result = LoggingAsyncMock('result')
        c.send_info = LoggingAsyncMock('info')
        c.send_error = LoggingAsyncMock('error')
        return c

    @pytest.fixture
    async def dbg(self,conn):
        return CommandLineDebugger(conn)


    results = {
        '00_angr_find.md': b'YXIACZSW',
        '01_angr_avoid.md': b'JLVUSGJZ',
        '02_angr_find_condition.md': b'OHYJUMBE',
        '03_angr_symbolic_registers.md': 'e9b37483 7aab5fde 8f5b48ea',
        '04_angr_symbolic_stack.md':'2089710965 12847883',
        '05_angr_symbolic_memory.md': 'OJQVXIVX LLEAOODW UVCWUVVC AJXJMVKA',
        '06_angr_symbolic_dynamic_memory.md':'OFIJHOXV FBQISOZO',
        "07_angr_symbolic_file.md": 'OBAXRUZT',
        "08_angr_constraints.md": 'ZEVKWROAYILRPZYB',
        "09_angr_hooks.md": b'QREPXOHPJPOQKQLKNOBMULEMGMLNHNIH',
        "14_angr_shared_library.md": 'TSDLQKWZ',
    }

    @pytest.mark.asyncio
    async def test_oregonctf_examples(self, dbg, conn):
        # for each .md file in the examples/malware.oregonctf.org directory run the script
        # and check the output

        for file in sorted(os.listdir("examples/malware.oregonctf.org")):
            if file.endswith(".md"):
                print(file)
                await dbg.handle("run_script 'examples/malware.oregonctf.org/" + file + "'")
                assert conn.send_result.call_args[0][0] == self.results[file]
                conn.send_result.reset_mock()
                conn.send_info.reset_mock()
                conn.send_error.reset_mock()