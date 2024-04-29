
import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from prompt_toolkit import PromptSession
import pytest

from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.connection import CliConnection
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
@patch.object(CliConnection,'send_event')
@patch.object(CommandLineDebugger,'handle', side_effect=[False])
@patch.object(PromptSession ,'prompt_async', side_effect=["help"])
async def test_loop(prompt, handle, send_event, server):
    
    await server.loop()
    prompt.assert_called_once()
    send_event.assert_called_once_with("Welcome to dAngr, the symbolic debugger. Type help or ? to list commands.")
    handle.assert_called_once_with('help')


