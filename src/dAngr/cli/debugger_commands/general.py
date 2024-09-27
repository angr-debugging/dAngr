import os

from dAngr.cli.models import State
from .base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from prompt_toolkit.shortcuts import ProgressBar
import angrutils

class GeneralCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    async def help(self, command: str|None = None):
        """
        Show dAngr help.

        Usage: help [command]

        Args:
        command (str|None): The command to show help for. If not provided, show general help.

        Short name: ?

        """
        if command:
            spec = self.debugger.get_command_spec(command)
            if spec is None:
                await self.send_error(f"Command '{command}' not found. Type 'help' or '?' for a list of available commands.")
            else:
                await self.debugger.list_args(spec)
        else:
             await self.debugger.list_commands()
