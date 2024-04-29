# Assuming all command classes are in debugger_commands.py
import re
import sys
from typing import List

from dAngr.cli.debugger_commands.base import get_cmd_name, get_short_cmd_name
from dAngr.exceptions import CommandError
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError

from dAngr.angr_ext.debugger import Debugger
from .connection import CliConnection
from .models import Breakpoint

from .debugger_commands import BaseCommand
from .debugger_commands.execution import *
from .debugger_commands.info import *
from .debugger_commands.breakpoints import *
from .debugger_commands.functions import *
from .debugger_commands.memory import *

def _auto_register_commands():
    commands = {}
    for name, obj in globals().items():
        if isinstance(obj, type) and issubclass(obj, BaseCommand) and obj is not BaseCommand:
            # Convert class name from CamelCase to snake_case
            cmd_name = get_cmd_name(obj)
            commands[cmd_name] = obj
    return commands
DEBUGGER_COMMANDS = _auto_register_commands()

class CommandLineDebugger(Debugger):
    def __init__(self, conn:CliConnection):
        super(CommandLineDebugger, self).__init__()
        self.conn = conn
        self.breakpoints:List[Breakpoint] = []
    def _get_command(self, command:str):
        if command in DEBUGGER_COMMANDS:
            cmd = DEBUGGER_COMMANDS[command](self)
        elif any([command == get_short_cmd_name(o) for o in DEBUGGER_COMMANDS.values()]):
            cmd = next(o for o in DEBUGGER_COMMANDS.values() if get_short_cmd_name(o) == command)(self)
            command = cmd.cmd_name
        else:
            help_str = f"Command '{command}' not found. Type 'help' or '?' for a list of available commands.\nWith help <command> you can get more information on a specific command."
            raise InvalidArgumentError(help_str)
        return cmd, command
    async def handle(self, command:str):
        command = command.strip()
        if ' ' in command: # has arguments
            command_name, command_args = command.strip().split(' ', 1)
        else: # no arguments
            command_name, command_args = command.strip(), None

        if command_name == "help" or command_name == "?":
            # List all commands or show help for a specific command
            if command_args:
                cmd, command_name = self._get_command(command_args)
                await self._list_args(cmd, command_args)
            else:
                await self._list_commands()
        else:
            # Execute the command
            try:
                cmd, command_name = self._get_command(command_name)
                if command_args is None and len(cmd.arg_specs)==0:
                    r = await cmd.execute()
                else:
                    inp = self._parse_arguments(cmd, command_args)
                    r = await cmd.execute(*inp)
                if r is not None:
                    await self.conn.send_event(r)
            except CommandError as e:
                await self.conn.send_error(e)

        if command_name == 'exit':
            return False
        else:
            return True

    async def _list_commands(self):
        table_data = [["Available commands:"]]
        package = ''
        EMPTY = "   "
        for command in DEBUGGER_COMMANDS.keys():
            # get module base name if different from the previous one
            if package != DEBUGGER_COMMANDS[command].__module__.split('.')[-2]:
                package = DEBUGGER_COMMANDS[command].__module__.split('.')[-2]
                table_data.append([EMPTY, f"{package}"])

            # don't list short commands
            name = DEBUGGER_COMMANDS[command].__name__
            if command != ''.join([i.lower() for i in name.replace('Command', '') if i.isupper()]):
                fnd = False
                # get name of others with the same class type listed as value
                for k,v in DEBUGGER_COMMANDS.items():
                    if v == DEBUGGER_COMMANDS[command] and k != command:
                        table_data.append([EMPTY,EMPTY, f"{command} ({k}):"])
                        fnd = True
                        break
                if not fnd:
                    table_data.append([EMPTY,EMPTY, f"{command}:"])
                table_data.append([EMPTY,EMPTY, EMPTY, DEBUGGER_COMMANDS[command](None).info.replace("\n", " ")])

        # Create HTML table
        html_table = ""
        for row in table_data:
            html_table += "\t"
            for cell in row:
                html_table += f"{cell}"
            html_table += "\n"
        

        # Create formatted HTML text with style
        formatted_html = f"{html_table}"
        await self.conn.send_event(formatted_html)

    async def _list_args(self, cmd :BaseCommand, command_name:str):
        if len(cmd.arg_specs)>0 or len(cmd.optional_args)>0:
            args = ', '.join([f"{a[0]} of type '{a[1].__name__ if a[1] else 'any'}'"  for a in cmd.arg_specs])
            optional_args = ', '.join([f"{a[0]} of type '{a[1].__name__ if a[1] else 'any'}'"  for a in cmd.optional_args])
            if optional_args and args:
                await self.conn.send_event(f"{cmd.info}\n  arguments: {args}\n  optional arguments: {optional_args}")
            else:
                if args:
                    await self.conn.send_event(f"{cmd.info}\n  arguments: {args}")
                else:
                    await self.conn.send_event(f"{cmd.info}\n  optional arguments: {optional_args}")
        else:
            await self.conn.send_event(f"{cmd.info}\n  No arguments required")

    def _parse_arguments(self,cmd :BaseCommand, user_input): 
        arg_specs = cmd.arg_specs + cmd.optional_args
        rex = ''
        cnt = len(arg_specs)
        for i in range(0,cnt):
            if i==cnt-1 and arg_specs[-1][1]==str:
                rex = rex + r"(.*)"
            else:
                rex = rex + r"(\S+)(?:\s+|$)"
        
        # Match the user input against the regex pattern
        try:
            match = re.match(rex, user_input)
        except TypeError as e:
            match = None
        # If no match is found, raise an InvalidArgumentError
        if not match:
            expected_arguments = ', '.join(arg_spec[0] for arg_spec in arg_specs)
            raise InvalidArgumentError(f"Invalid input format. Expected arguments: {expected_arguments}")

        # Extract matched groups
        parsed_args = match.groups()

        # If there are fewer matched groups than expected arguments, raise an InvalidArgumentError
        if len(parsed_args) < len(arg_specs):
            expected_arguments = ', '.join(arg_spec[0] for arg_spec in arg_specs)
            raise InvalidArgumentError(f"Invalid input format. Expected arguments: {expected_arguments}")

        # Map argument names to parsed values
        parsed_args_list = []
        for (arg_name, arg_type), arg_value in zip(arg_specs, parsed_args):
            # Remove surrounding double quotes if present
            if arg_value.startswith('"') and arg_value.endswith('"'):
                arg_value = arg_value[1:-1]
            # Convert the argument value to the specified type
            try:
                # Convert the argument value to int if the type is int and the value starts with '0x'
                if (arg_type == int or arg_type is None) and arg_value.startswith('0x'):
                    parsed_args_list.append(int(arg_value, 16))
                elif arg_type is None:
                    try: #Warning: unsafe code
                        parsed_args_list.append(eval(arg_value))
                    except:
                        raise InvalidArgumentError(f"Failed to convert argument '{arg_name}' to type '{arg_type} from {arg_value}'")
                else: 
                    if arg_type == bool:
                        if arg_value.lower() == 'true':
                            parsed_args_list.append(True)
                        elif arg_value.lower() == 'false':
                            parsed_args_list.append(False)
                        else:
                            raise InvalidArgumentError(f"Failed to convert argument '{arg_name}' to type '{arg_type} from {arg_value}'")
                    else:
                        parsed_args_list.append(arg_type(arg_value))
            except ValueError:
                raise InvalidArgumentError(f"Failed to convert argument '{arg_name}' to type '{arg_type} from {arg_value}'")

        # If there's remaining input, join it into a single string and assign it to the last argument
        if len(parsed_args_list) < len(arg_specs):
            if not arg_specs[-1][1] == str:
                raise InvalidArgumentError(f"Failed to convert argument '{arg_specs[-1][0]}' to type '{arg_specs[-1][1].__name__}' from '{parsed_args_list[-1]}{' '.join(parsed_args[len(arg_specs) - 1:])}'")
            parsed_args_list.append(' '.join(parsed_args[len(arg_specs) - 1:]))
        return parsed_args_list


