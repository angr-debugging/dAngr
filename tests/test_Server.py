
import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from prompt_toolkit import PromptSession
import pytest

from dAngr.cli.command_line_debugger import DEBUGGER_COMMANDS, CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.server import Server


@pytest.fixture
def server():
    return Server()


@patch('asyncio.run',new_callable=Mock)
def test_start_server(asyncio_run,server):

        def run_coroutine_sync(coro):
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(coro)

        asyncio_run.side_effect = run_coroutine_sync


        server.start_server()
        asyncio_run.assert_called_once()

@pytest.mark.asyncio
@patch.object(CliConnection,'send_info')
@patch.object(CommandLineDebugger,'handle', side_effect=[False])
@patch.object(PromptSession ,'prompt_async', side_effect=["help"])
async def test_loop(prompt, handle, send_info, server):
    
    await server.loop()
    prompt.assert_called_once()
    send_info.assert_called_once_with("Welcome to dAngr, the symbolic debugger. Type help or ? to list commands.")
    handle.assert_called_once_with('help')

@pytest.mark.asyncio
async def test_check_shortnames(server):
    conn = CliConnection()
    dbg = CommandLineDebugger(conn)

            # get duplicate short commands and print short and fullname
    for cmd in DEBUGGER_COMMANDS.values():
        
        if cmd.name in ["start","continue"]:
            break
        assert not any([o.short_name == cmd.short_name for o in DEBUGGER_COMMANDS.values() if o != cmd]), f"Duplicate short command {cmd.short_name}"

