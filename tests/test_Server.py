
import asyncio
from unittest.mock import Mock, MagicMock, patch
from prompt_toolkit import PromptSession
import pytest

from dAngr.cli.command_line_debugger import DEBUGGER_COMMANDS, CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.server import Server


@pytest.fixture
def server():
    server = Server()
    server.start_server = Mock()
    # server.loop = Mock()
    return server


@patch('asyncio.run',new_callable=Mock)
def test_start_server(asyncio_run,server):

        def run_coroutine_sync(coro):
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(coro)

        asyncio.run(server.start_server())


        server.start_server()
        asyncio_run.assert_called_once()


@patch.object(CliConnection,'send_info')
@patch.object(CommandLineDebugger,'handle', side_effect=[False])
@patch.object(PromptSession ,'prompt', side_effect=["help"])
def test_loop(prompt, handle, send_info, server):
    
    server.loop()
    prompt.assert_called_once()
    send_info.assert_called_once_with("Welcome to dAngr, the symbolic debugger. Type help or ? to list commands.")
    handle.assert_called_once_with('help', False)


def test_check_shortnames(server):
    conn = CliConnection()
    dbg = CommandLineDebugger(conn)

            # get duplicate short commands and print short and fullname
    for cmd in DEBUGGER_COMMANDS.values():
        
        if cmd.name in ["start","continue"]:
            break

        if any([o.short_name and o.short_name == cmd.short_name for o in DEBUGGER_COMMANDS.values() if o != cmd]):
            print(f"Short name: {cmd.short_name} Full name: {cmd.name}")
        assert not any([o.short_name and o.short_name == cmd.short_name for o in DEBUGGER_COMMANDS.values() if o != cmd]), f"Duplicate short command {cmd.short_name}"


def test_check_cmdnames(server):
    conn = CliConnection()
    dbg = CommandLineDebugger(conn)

            # get duplicate short commands and print short and fullname
    for cmd in DEBUGGER_COMMANDS.values():
        
        if cmd.name in ["start","continue"]:
            break
        assert not any([o.name and o.name == cmd.name for o in DEBUGGER_COMMANDS.values() if o != cmd]), f"Duplicate short command {cmd.name}"

