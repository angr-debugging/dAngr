# Assuming all command classes are in debugger_commands.py
import os
import re
import threading
from typing import Callable, Dict, List, cast
from enum import Enum
import typing

import angr

from prompt_toolkit.styles import Style
from prompt_toolkit.styles.named_colors import NAMED_COLORS

from dAngr.angr_ext.step_handler import StepHandler, StopReason
from dAngr.angr_ext.utils import get_bb_end_address
from dAngr.cli.debugger_commands.base import get_cmd_name, get_short_cmd_name
from dAngr.cli.filters import Filter, FilterList
from dAngr.exceptions import CommandError
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError

from dAngr.angr_ext.debugger import Debugger
from dAngr.utils.utils import get_union_members, parse_arguments
from .cli_connection import CliConnection
from .models import Breakpoint

from .debugger_commands import *
# from .debugger_commands.execution import *
# from .debugger_commands.info import *
# from .debugger_commands.execution.breakpoints import *
# from .debugger_commands.functions import *
# from .debugger_commands.memory import *

def _auto_register_commands():
    commands:Dict[str,type[BaseCommand]] = {}
    for name, obj in globals().items():
        if isinstance(obj, type) and issubclass(obj, BaseCommand) and obj is not BaseCommand:
            # Convert class name from CamelCase to snake_case
            cmd_name = get_cmd_name(obj)
            commands[cmd_name] = obj
    return commands
DEBUGGER_COMMANDS = _auto_register_commands()

class CommandLineDebugger(Debugger,StepHandler):
    def __init__(self, conn:CliConnection):
        Debugger.__init__(self, conn)
        self._breakpoints:FilterList = FilterList()
        self._exclusions:List[Filter] = []
        self.http_server = None
        self.http_thread = None

    @property
    def breakpoints(self)->FilterList:
        self.throw_if_not_initialized()
        return self._breakpoints
    
    @property
    def exclusions(self)->List[Filter]:
        self.throw_if_not_initialized()
        return self._exclusions

    # step handler methods
    async def handle_output(self, output:str):
        await self.conn.send_output(f"{output}")
    
    async def handle_step(self,reason:StopReason, state:angr.SimState|None):
        if reason == StopReason.TERMINATE:
            await self.conn.send_info(f"Terminated.") # type: ignore
        elif state is None:
            await self.conn.send_warning(f"Stopped with unknown reason.")
        elif reason == StopReason.STEP:
            await self.conn.send_info(f"Stepped to: {hex(state.addr)}.") # type: ignore
        elif reason == StopReason.BREAKPOINT:
            for f in self.breakpoints.get_matching_filter(state):
                await self.conn.send_info(f"Break: {f}.")
        elif reason == StopReason.PAUSE:
            await self.conn.send_info(f"Paused at: {hex(state.addr)}.") # type: ignore
        else:
            await self.conn.send_warning(f"Stopped with unknown reason at: {hex(start)}.") # type: ignore

    async def handle(self, command:str):
        if not command:
            return True
        command = command.strip()
        if ' ' in command: # has arguments
            command_name, command_args = command.strip().split(' ', 1)
        else: # no arguments
            command_name, command_args = command.strip(), ""

        if command_name == "help" or command_name == "?":
            # List all commands or show help for a specific command
            if command_args:
                cmd = self._get_command(command_args)
                await self._list_args(cmd)
            else:
                await self._list_commands()
        else:
            # Execute the command
            try:
                cmd = self._get_command(command_name)
                #if cmd not in viewer package, clear output
                if not cmd.__module__.startswith('dAngr.cli.debugger_commands.viewer'):
                    cast(CliConnection,self.conn).clear_output()

                inp = self._parse_arguments(cmd, command_args)
                r = await cmd.execute_base(*inp)
                if r is not None:
                    await self.conn.send_result(str(r))
            except CommandError as e:
                await self.conn.send_error(e)

        if command_name == 'exit':
            return False
        else:
            return True
        
    def launch_file_server(self):
        base_path = "/tmp/web"
        # set file_index to 1 + nr of files in path
        if self.http_server is None:
            if not os.path.exists(base_path):
                os.makedirs(base_path)
            else:
                for f in os.listdir(base_path):
                    os.remove(os.path.join(base_path, f))
            import http.server
            class Handler(http.server.SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs, directory=base_path)

            import socketserver
            PORT = 8000
            handler = Handler
            self.http_server = socketserver.TCPServer(("127.0.0.1", PORT), handler)
            #serve files in a separate thread
            self.http_thread = threading.Thread(target=self.http_server.serve_forever).start()
        return base_path

    def __del__(self):
        if self.http_server is not None:
            self.http_server.shutdown()
            self.http_server.server_close()
        if self.http_thread is not None:
            self.http_thread.join()


    def _get_command(self, command:str):
        if command in DEBUGGER_COMMANDS:
            return DEBUGGER_COMMANDS[command](self)
        elif cmd := next((o for o in DEBUGGER_COMMANDS.values() if command == o(self).short_cmd_name), None):
            return cmd(self)
        else:
            help_str = f"Command '{command}' not found. Type 'help' or '?' for a list of available commands.\nWith help <command> you can get more information on a specific command."
            raise InvalidArgumentError(help_str)

    

    async def _list_commands(self):
        style = Style.from_dict({
            'title': '',
            'package': 'yellow italic',
            'command': 'blue bold',
            'shortcmd': 'italic',
            'info': 'darkgray',
        })
        table_data = [[],["<title>Available commands:</title>"]]
        package = ''
        EMPTY = "\t"
        for command in DEBUGGER_COMMANDS.keys():
            cmd = DEBUGGER_COMMANDS[command](self)
            # get module base name if different from the previous one
            if package != type(cmd).__module__.split('.')[-2]:
                package = cmd.__module__.split('.')[-2]
                table_data.append([EMPTY, f"<package>{package}</package>"])

            table_data.append([EMPTY, EMPTY,f"<command>{command} <shortcmd>({cmd.short_cmd_name})</shortcmd></command>:"])
            # get first line of info and append ... if there are more lines
            first, sec = cmd.info.split('\n', 1) if '\n' in cmd.info else (cmd.info, '')
            if sec:
                first += "..."
            if len(first.strip("..."))>50:
                first = first[:50] + "..."
            
            table_data.append([EMPTY, EMPTY, EMPTY, f"<info>{first}</info>"])
            table_data.append([])

        # Create HTML table
        html_table = ""
        for row in table_data:
            html_table += "\t"
            for cell in row:
                html_table += f"{cell}"
            html_table += "\n"
        

        # Create formatted HTML text with style
        formatted_html = f"{html_table}"
        await self.conn.send_result(formatted_html,style=style)

    async def _list_args(self, cmd :BaseCommand):
        style = Style.from_dict({
            'title': '',
            'command': 'blue bold',
            'info': '',
            'argument': 'green',
            'arg_info': 'darkgray italic',
            'extra_info': 'gray italic',
        })
        EMPTY = "\t"
        table_data = [[]]
        # command structure
        # print command name, followed by required args separated by comma, then optional args in square brackets
        req = " " + " ".join([f"<argument>{a[0]}</argument>" for a in cmd.arg_specs])
        opt = " " + " ".join([f"<argument>[{a[0]}]</argument>" for a in cmd.optional_args])
        table_data.append([EMPTY, f"Usage: <command>{cmd.cmd_name}{req.rstrip()}{opt.rstrip()}</command>"])
        table_data.append([EMPTY, f"Short name: <command>{cmd.short_cmd_name}</command>"])
        for l in cmd.info.split("\n"):
            table_data.append([EMPTY, f"<info>{l}</info>"])         
        table_data.append([])
        if cmd.arg_specs or cmd.optional_args:
            if cmd.arg_specs:
                table_data.append([EMPTY, "<info>Arguments:</info>"])
            first = True
            for a in cmd.arg_specs:                
                table_data.append([EMPTY, EMPTY, f"<argument>{a[0]}</argument> <arg_info>({a[1].__name__ if a[1] else 'any'})</arg_info>"])
                if len(a)>2:
                    table_data.append([EMPTY, EMPTY, EMPTY, f"<arg_info>{a[2]}</arg_info>"])
            if cmd.optional_args:
                table_data.append([EMPTY, "<info>Optional Arguments:</info>"]) 
                for a in cmd.optional_args:
                    table_data.append([EMPTY, EMPTY, f"<argument>{a[0]}</argument> <arg_info>({a[1].__name__ if a[1] else 'any'})\t</arg_info>"])
                    if len(a)>2:
                        table_data.append([EMPTY, EMPTY, EMPTY, f"{a[2]}"])

        if cmd.extra_info:
            table_data.append([EMPTY, "<info>Extra info:</info>"])
            for l in cmd.extra_info.split("\n"):
                table_data.append([EMPTY, EMPTY, f"<extra_info>{l}</extra_info>"])

        html_table = ""
        for row in table_data:
            html_table += "\t"
            for cell in row:
                html_table += f"{cell}"
            html_table += "\n"
        
        await self.conn.send_result(html_table, style=style)

    def _parse_arguments(self,cmd :BaseCommand, user_input:str)->List: 

        parsed_args = parse_arguments(user_input, " ")

        if len(parsed_args) < len(cmd.arg_specs):
            expected_arguments = ', '.join(arg_spec[0] for arg_spec in cmd.arg_specs)
            if len(cmd.optional_args)>0:
                optional_arguments = ", optional arguments: "+', '.join(arg_spec[0] for arg_spec in cmd.optional_args)
            else:
                optional_arguments = ""
            raise InvalidArgumentError(f"Invalid input format. Expected arguments: {expected_arguments}{optional_arguments}")
        arg_specs = cmd.arg_specs + cmd.optional_args
        if len(parsed_args) > len(arg_specs):

            if len(arg_specs)>0 and arg_specs[-1][1] == str:
                # If the last argument is a string, join the remaining input into a single string and remove the rest
                parsed_args[len(arg_specs)-1] = ' '.join(parsed_args[len(arg_specs) - 1:])
                parsed_args = parsed_args[:len(cmd.arg_specs+cmd.optional_args)]
            else:
                raise InvalidArgumentError(f"Too many arguments. Expected {len(cmd.arg_specs) + len(cmd.optional_args)} but got {len(parsed_args)}")

        # Map argument names to parsed values
        parsed_args_list = []
        for (arg_name, arg_type,_), arg_value in zip(cmd.arg_specs+cmd.optional_args, parsed_args):
            if arg_value is None:
                break # must be because of optional arguments

            # Convert the argument value to the specified type
            try:
                # Convert the argument value to int if the type is int and the value starts with '0x'
                # str can be word or words in double quotes
                # bool can be word True or False
                # bytes is python bytes b'...'
                # int can be int or hex
                # if arg_type is class and subclass of Enum, parse arg_value to the enum type
                if isinstance(arg_type,type) and issubclass(arg_type, Enum): # type: ignore
                    parsed_args_list.append(arg_type[arg_value.upper()])
                    continue
                types = [arg_type]
                if members := get_union_members(arg_type):
                    types = members
                
                if bool in types:
                    if arg_value.lower() == 'true' or arg_value.lower() == 'false':
                        parsed_args_list.append(arg_value.lower() == 'true')
                        continue
                if bytes in types:
                    if (arg_value.startswith('b"') and arg_value.endswith('"') )or (arg_value.startswith("b'") and arg_value.endswith("'")):
                        parsed_args_list.append(bytes(arg_value[2:-1], 'utf-8'))
                        continue

                if int in types:
                    if arg_value.startswith('0x'):
                        parsed_args_list.append(int(arg_value, 16))
                        continue
                    else:
                        if arg_value.isnumeric():
                            parsed_args_list.append(int(arg_value))
                            continue
                if str in types:
                    if arg_value.startswith(('\'','"')) and arg_value.endswith(('\'','"')):
                        parsed_args_list.append(arg_value[1:-1])
                    else:
                        parsed_args_list.append(arg_value)
                    continue
                # value not in any of the types
                for tp in types:
                    description= f"Failed to convert argument '{arg_name}' to type '{tp} from {arg_value}'"
                    raise InvalidArgumentError(description)

                # if members:
                #     types = members
                # for tp in types:
                #     if tp == str:
                #         parsed_args_list.append(arg_value.strip("\"'"))
                #         break
                #     elif (tp == int or tp is None) and arg_value.startswith('0x'):
                #         parsed_args_list.append(int(arg_value, 16))
                #         break
                #     elif tp is None:
                #         try: #Warning: unsafe code
                #             parsed_args_list.append(eval(arg_value))
                #             break
                #         except:
                #             raise InvalidArgumentError(f"Failed to convert argument '{arg_name}' to type '{tp} from {arg_value}'")
                #     else:
                #         if tp == bool:
                #             if arg_value.lower() == 'true':
                #                 parsed_args_list.append(True)
                #                 break
                #             elif arg_value.lower() == 'false':
                #                 parsed_args_list.append(False)
                #                 break
                #             else:
                #                 raise InvalidArgumentError(f"Failed to convert argument '{arg_name}' to type '{tp} from {arg_value}'")
                #         # else:
                        #     #if arg_type is union including str, if the value is not one of the other types, it is a string
                            
                        #     arg_value = eval(arg_value)
                        #     parsed_args_list.append(typing.cast(arg_type,arg_value)) # type: ignore
            except ValueError:
                raise InvalidArgumentError(f"Failed to convert argument '{arg_name}' to type '{arg_type} from {arg_value}'")

        # If there's remaining input, join it into a single string and assign it to the last argument
        if len(parsed_args_list) < len(cmd.arg_specs):
            arg_specs = cmd.arg_specs + cmd.optional_args
            if not arg_specs[-1][1] == str:
                raise InvalidArgumentError(f"Failed to convert argument '{arg_specs[-1][0]}' to type '{arg_specs[-1][1].__name__}' from '{parsed_args_list[-1]}{' '.join(parsed_args[len(arg_specs) - 1:])}'")
            parsed_args_list.append(' '.join(parsed_args[len(arg_specs) - 1:]))
        return parsed_args_list


    async def run(self, check_until:Callable[[angr.SimulationManager],StopReason] = lambda _:StopReason.NONE, exclude:Callable[[angr.SimState],bool] = lambda _:False):
        u = check_until
        exclusions = self.exclusions
        def check(simgr:angr.SimulationManager):
            r = u(simgr)
            if r != StopReason.NONE:
                return r
            state = simgr.one_active
            if self.breakpoints.filter(state):
                return StopReason.BREAKPOINT
            return StopReason.NONE

        def _exclude(state:angr.SimState)->bool:
            if exclude(state):
                return True
            return any([f.filter(state) for f in exclusions])
        
        await self._run(self, check,_exclude)