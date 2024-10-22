
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


    # results = {
    #     '00_angr_find.md': b'YXIACZSW',
    #     '01_angr_avoid.md': b'JLVUSGJZ',
    #     '02_angr_find_condition.md': b'OHYJUMBE',
    #     '03_angr_symbolic_registers.md': 'e9b37483 7aab5fde 8f5b48ea',
    #     '04_angr_symbolic_stack.md':'2089710965 12847883',
    #     '05_angr_symbolic_memory.md': 'OJQVXIVX LLEAOODW UVCWUVVC AJXJMVKA',
    #     '06_angr_symbolic_dynamic_memory.md':'OFIJHOXV FBQISOZO',
    #     "07_angr_symbolic_file.md": 'OBAXRUZT',
    #     "08_angr_constraints.md": 'ZEVKWROAYILRPZYB',
    #     "09_angr_hooks.md": b'QREPXOHPJPOQKQLKNOBMULEMGMLNHNIH',
    #     "10_angr_simprocedures.md": b'MTMDRONBBNSAAMNS',
    #     "11_angr_sim_scanf.md": '1447907916 1146768724',
    #     "13_angr_static_binary.md": b'EADQYLAR',
    #     "14_angr_shared_library.md": 'TSDLQKWZ',
    #     "15_angr_arbitrary_read.md": '2358019 AAAAAAAAAAAAAAAAWISO'
    # }

    # @pytest.mark.asyncio
    # async def test_oregonctf_examples(self, conn):
    #     # for each .md file in the examples/malware.oregonctf.org directory run the script
    #     # and check the output

    #     for file in sorted(os.listdir("examples/malware.oregonctf.org")):
    #         if file.endswith(".md"):
    #             print(file)
    #             dbg = CommandLineDebugger(conn)
    #             await dbg.handle("run_script 'examples/malware.oregonctf.org/" + file + "'")
    #             assert conn.send_result.call_args[0][0] == self.results[file], f"Failed on {file}"
    #             conn.send_result.reset_mock()
    #             conn.send_info.reset_mock()
    #             conn.send_error.reset_mock()
    
    @pytest.mark.asyncio
    async def test_00_angr_find(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/00_angr_find.md'")
        assert conn.send_result.call_args[0][0] == b'YXIACZSW'
    
    @pytest.mark.asyncio
    async def test_01_angr_avoid(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/01_angr_avoid.md'")
        assert conn.send_result.call_args[0][0] == b'JLVUSGJZ'

    @pytest.mark.asyncio
    async def test_02_angr_find_condition(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/02_angr_find_condition.md'")
        assert conn.send_result.call_args[0][0] == b'OHYJUMBE'
    
    @pytest.mark.asyncio
    async def test_03_angr_symbolic_registers(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/03_angr_symbolic_registers.md'")
        assert conn.send_result.call_args[0][0] == 'e9b37483 7aab5fde 8f5b48ea'

    @pytest.mark.asyncio
    async def test_04_angr_symbolic_stack(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/04_angr_symbolic_stack.md'")
        assert conn.send_result.call_args[0][0] == '2089710965 12847883'
    
    @pytest.mark.asyncio
    async def test_05_angr_symbolic_memory(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/05_angr_symbolic_memory.md'")
        assert conn.send_result.call_args[0][0] == 'OJQVXIVX LLEAOODW UVCWUVVC AJXJMVKA'

    @pytest.mark.asyncio
    async def test_06_angr_symbolic_dynamic_memory(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/06_angr_symbolic_dynamic_memory.md'")
        assert conn.send_result.call_args[0][0] == 'OFIJHOXV FBQISOZO'

    @pytest.mark.asyncio
    async def test_07_angr_symbolic_file(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/07_angr_symbolic_file.md'")
        assert conn.send_result.call_args[0][0] == 'OBAXRUZT'

    @pytest.mark.asyncio
    async def test_08_angr_constraints(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/08_angr_constraints.md'")
        assert conn.send_result.call_args[0][0] == 'ZEVKWROAYILRPZYB'

    @pytest.mark.asyncio
    async def test_09_angr_hooks(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/09_angr_hooks.md'")
        assert conn.send_result.call_args[0][0] == b'QREPXOHPJPOQKQLKNOBMULEMGMLNHNIH'

    @pytest.mark.asyncio
    async def test_10_angr_simprocedures(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/10_angr_simprocedures.md'")
        assert conn.send_result.call_args[0][0] == b'MTMDRONBBNSAAMNS'

    @pytest.mark.asyncio
    async def test_11_angr_sim_scanf(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/11_angr_sim_scanf.md'")
        assert conn.send_result.call_args[0][0] == '1447907916 1146768724'

    @pytest.mark.asyncio
    async def test_13_angr_static_binary(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/13_angr_static_binary.md'")
        assert conn.send_result.call_args[0][0] == b'EADQYLAR'

    @pytest.mark.asyncio
    async def test_14_angr_shared_library(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/14_angr_shared_library.md'")
        assert conn.send_result.call_args[0][0] == 'TSDLQKWZ'

    @pytest.mark.asyncio
    async def test_15_angr_arbitrary_read(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/15_angr_arbitrary_read.md'")
        assert conn.send_result.call_args[0][0][:7] == '2358019'
        assert conn.send_result.call_args[0][0][-5:-1] == 'WISO'

    @pytest.mark.asyncio
    async def test_16_angr_arbitrary_write(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/16_angr_arbitrary_write.md'")
        assert conn.send_result.call_args[0][0][:7] == '6712341'
        assert conn.send_result.call_args[0][0][8:16] == 'NEDVTNOP'
        assert conn.send_result.call_args[0][0][-4:] == '<RCM'

    @pytest.mark.asyncio
    async def test_17_angr_arbitrary_jump(self, conn):
        dbg = CommandLineDebugger(conn)
        await dbg.handle("run_script 'examples/malware.oregonctf.org/17_angr_arbitrary_jump.md'")
        assert conn.send_result.call_args[0][0] == 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCPRCMCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'

