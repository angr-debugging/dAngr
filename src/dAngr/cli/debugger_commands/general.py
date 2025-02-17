import os

from dAngr.cli.models import State
from .base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from prompt_toolkit.shortcuts import ProgressBar
from dAngr.utils.loggers import dAngr_log_config

class GeneralCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    def help(self, command: str|None = None):
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
                self.send_error(f"Command '{command}' not found. Type 'help' or '?' for a list of available commands.")
            else:
                self.debugger.list_args(spec)
        else:
             self.debugger.list_commands()

    def set_log_level(self, module:str, level:str = "DEBUG"):
        """
        Set the log level for a module.

        Usage: set_log_level module level

        Args:
        module (str): The module to set the log level for.
        level (str): The log level to set. Default is DEBUG. Valid values are "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "NOTSET".

        Short name: log

        """
        dAngr_log_config.set_module(module, level)
        self.send_info(f"Set log level for module '{module}' to {level}")
        
    def list_loggers(self):
        """
        List all loggers.

        Usage: list_loggers

        Short name: ll

        """
        return dAngr_log_config.list_modules_from_loggers()
