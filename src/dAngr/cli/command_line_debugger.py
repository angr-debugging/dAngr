# Assuming all command classes are in debugger_commands.py
import os
import threading
from typing import Callable, Dict, List, Tuple, cast, override

import angr


import claripy
from prompt_toolkit.styles import Style
from prompt_toolkit.styles.named_colors import NAMED_COLORS

from dAngr.angr_ext.step_handler import StepHandler, StopReason
from dAngr.cli.debugger_commands import *
from dAngr.cli.debugger_commands.base import BuiltinFunctionDefinition
from dAngr.cli.filters import Filter, FilterList
from dAngr.cli.grammar.parser import parse_input
from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.cli.grammar.expressions import Object


from dAngr.exceptions import CommandError

from dAngr.angr_ext.debugger import Debugger
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from dAngr.utils.utils import get_union_members
from .cli_connection import CliConnection
from .debugger_commands import *


def _auto_register_commands() -> Dict[str, BuiltinFunctionDefinition]:
    commands:Dict[str, BuiltinFunctionDefinition] = {}
    for name, obj in globals().items():
        if isinstance(obj, type) and issubclass(obj, BaseCommand) and obj is not BaseCommand:
            specs = getattr(obj, "__cmd_specs__", None)
            if specs:
                for command in specs:
                    spec = specs[command]
                    # Add the command to the list of available commands
                    commands[spec.name] = spec
    return commands
DEBUGGER_COMMANDS = _auto_register_commands()

EMPTY = "\t"

class dAngrExecutionContext(ExecutionContext):
    def __init__(self, debugger:Debugger, commands:Dict[str, BuiltinFunctionDefinition]):
        super().__init__()
        self._debugger = debugger
        #add commands to context
        self._definitions.update(commands)
    
    @property
    def debugger(self)->Debugger:
        return self._debugger
    # @override
    # async def get_argument_value(self, arg):
    #     if isinstance(arg, Memory):
    #         return self._debugger.get_memory(arg.address, arg.size)
    #     elif isinstance(arg, Register):        
    #         return self._debugger.get_register_value(arg.name)
    #     elif isinstance(arg, ValueObject):
    #         return self._debugger.get_symbol(arg.name)
    #     else:
    #         return await super().get_argument_value(arg)

class CommandLineDebugger(Debugger,StepHandler):
    def __init__(self, conn:CliConnection):
        Debugger.__init__(self, conn)
        self._breakpoints:FilterList = FilterList()
        self._exclusions:List[Filter] = []
        self.http_server = None
        self.http_thread = None
        self.context:dAngrExecutionContext = dAngrExecutionContext(self, DEBUGGER_COMMANDS)

    def __del__(self):
        if self.http_server is not None:
            self.http_server.shutdown()
            self.http_server.server_close()
        if self.http_thread is not None:
            self.http_thread.join()
    
    @property
    def trigger_points(self)->FilterList:
        self.throw_if_not_initialized()
        return self._breakpoints
    
    @property
    def exclusions(self)->List[Filter]:
        self.throw_if_not_initialized()
        return self._exclusions

    # step callback methods
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
            for f in self.trigger_points.get_matching_filter(state):
                await self.conn.send_info(f"Break: {f}.")
        elif reason == StopReason.PAUSE:
            await self.conn.send_info(f"Paused at: {hex(state.addr)}.") # type: ignore
        else:
            await self.conn.send_warning(f"Stopped with unknown reason at: {hex(start)}.") # type: ignore

    # command methods
    async def handle(self, command:str):
        try:
            if not command:
                return True
            elif command == "exit":
                return False
            # command = command.strip()
            script = parse_input(command)
            if not script:
                await self.conn.send_info("No command entered.")
                return True
            r = await script(self.context)
            if r is not None:
                if isinstance(r, int):
                    r = hex(r)
                await self.conn.send_result(str(r))
            return True
        except CommandError as e:
            await self.conn.send_error(e)
            return True
            # raise e
        
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

    def get_command_spec(self, command:str)->BuiltinFunctionDefinition|None:
        return DEBUGGER_COMMANDS.get(command, None)

    def list_commands_data(self, withArgs:bool = False):
        table_data = [[],["<title>Available commands:</title>"]]
        package = ''
        # get a list of keys from the dictionary sorted based on package and name
        list_of_keys = sorted((k for k in DEBUGGER_COMMANDS.keys() if DEBUGGER_COMMANDS[k].short_name!= k ), key=lambda x: (DEBUGGER_COMMANDS[x].package, x))
        for command in list_of_keys:
            spec = DEBUGGER_COMMANDS[command]
            if command != spec.name:
                continue
            # get module base name if different from the previous one
            if package != spec.package:
                package = spec.package
                table_data.append([EMPTY, f"<package>{package}</package>"])

            table_data.append([EMPTY, EMPTY,f"<command>{command} <shortcmd>({spec.short_name})</shortcmd></command>:"])
            if not withArgs:
                # get first line of info and append ... if there are more lines
                first, sec = spec.description.split('\n', 1) if '\n' in spec.description else (spec.description, '')
                if sec:
                    first += "..."
                if len(first.strip("..."))>50:
                    first = first[:50] + "..."
                
                table_data.append([EMPTY, EMPTY, EMPTY, f"<info>{first}</info>"])
            else:
                table_data.extend(self.list_args_table(spec,[EMPTY,EMPTY,EMPTY]))
            table_data.append([])
        style = Style.from_dict({
            'title': '',
            'package': 'yellow italic',
            'command': 'blue bold',
            'shortcmd': 'italic',
            'info': 'darkgray',
        })
        return table_data, style
    def list_args_table(self, spec :BuiltinFunctionDefinition,indent = []) -> Tuple[List[List[str]],Style]:
        style = Style.from_dict({
            'title': '',
            'command': 'blue bold',
            'info': '',
            'argument': 'green',
            'arg_info': 'darkgray italic',
            'extra_info': 'gray italic',
        })
        table_data = [[]]

        # command structure
        # print command name, followed by required args separated by comma, then optional args in square brackets
        required = spec.required_arguments
        optional = spec.optional_arguments
        req = " " + " ".join([f"<argument>{a.name}</argument>" for a in required])
        opt = " " + " ".join([f"<argument>[{a.name}]</argument>" for a in optional])
        table_data.append([EMPTY, f"Usage: <command>{spec.name}{req.rstrip()}{opt.rstrip()}</command>"])
        table_data.append([EMPTY, f"Short name: <command>{spec.short_name}</command>"])
        for l in spec.description.split("\n"):
            table_data.append([EMPTY, f"<info>{l}</info>"])         
        table_data.append([])
        if spec.args:
            if required:
                table_data.append([EMPTY, "<info>Arguments:</info>"])
            for a in required:                
                if a.dtype:
                    if members:= get_union_members(a.name):
                        tp = " or ".join([m.__name__ for m in members])
                    else:
                        tp = a.dtype.__name__
                else: tp ="any"
                table_data.append([EMPTY, EMPTY, f"<argument>{a.name}</argument> <arg_info>({tp})</arg_info>"])
                if a.description:
                    table_data.append([EMPTY, EMPTY, EMPTY, f"<arg_info>{a.description}</arg_info>"])
            if optional:
                table_data.append([EMPTY, "<info>Optional Arguments:</info>"]) 
                for a in optional:
                    if a.dtype:
                        if members:= get_union_members(a.dtype):
                            tp = " or ".join([m.__name__ for m in members])
                        else:
                            tp = a.dtype.__name__
                    else: tp ="any"
                    table_data.append([EMPTY, EMPTY, f"<argument>{a.name}</argument> <arg_info>({tp})\t</arg_info>"])
                    if a.dtype:
                        table_data.append([EMPTY, EMPTY, EMPTY, f"{a.description}"])

        if spec.example:
            table_data.append([EMPTY, "<info>Example:</info>"])
            for l in spec.example.split("\n"):
                table_data.append([EMPTY, EMPTY, f"<extra_info>{l}</extra_info>"])
        #insert indent to each row:
        for i in range(len(table_data)):
            table_data[i] = indent + table_data[i]
        return table_data, style


    async def render_argument(self, value:int|bytes|str|Object, make_concrete:bool ):
        val = None
        if isinstance(value, int):
            val = self.to_bytes(value)
            if not make_concrete:
                val = claripy.BVV(value, len(val)*8)
        elif isinstance(value, bytes):
            if not make_concrete:
                val = claripy.BVV(value)
            pass
        elif isinstance(value, str):
            val = self.to_bytes(value)
            if not make_concrete:
                val = claripy.BVV(val)
        elif isinstance(value, Object):
            val = await value(context=self.context)
        if val == None:
            raise DebuggerCommandError(f"Could not convert value {value}")
        return val
    
    async def list_commands(self, withArgs:bool = False):

        table_data, style = self.list_commands_data(withArgs)
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

    async def list_args(self, spec :BuiltinFunctionDefinition):
        table_data, style = self.list_args_table(spec)

        html_table = ""
        for row in table_data:
            html_table += "\t"
            for cell in row:
                html_table += f"{cell}"
            html_table += "\n"
        
        await self.conn.send_result(html_table, style=style)
    # def _parse_arguments(self,spec :FunctionDefinition, user_input:str)->List: 

    #     parsed_args = parse_arguments(user_input, " ")

    #     named_args = {}
    #     positional_args = []
    #     # split parsed arguments into named and positional arguments
    #     for arg in parsed_args:
    #         if m := re.match(r"^([a-zA-Z0-9_]+)=(.*)$", arg):
    #             name = m.group(1)
    #             value = m.group(2)
    #             named_args[name] = value
    #         else:
    #             # if there exist named arguments, this should fail
    #             if named_args:
    #                 raise InvalidArgumentError(f"Named arguments must be placed after positional arguments")
    #             positional_args.append(arg)
    #     # insert named arguments into the correct position
    #     args = spec.args
    #     input_args = positional_args
    #     for arg_name, arg_value in named_args.items():
    #         if arg_name not in args:
    #             raise InvalidArgumentError(f"Invalid argument '{arg_name}'")
    #         arg_index = args.index(arg_name)
    #         if arg_index < len(positional_args):
    #             input_args.insert(arg_index, arg_value)
    #         else:
    #             input_args.append(arg_value)
        
    #     required = spec.required_arguments
    #     optional = spec.optional_arguments
    #     if len(input_args) < len(required):
    #         expected_arguments = ', '.join(arg_spec.name for arg_spec in required)
    #         if len(optional)>0:
    #             optional_arguments = ", optional arguments: "+', '.join(arg_spec.name for arg_spec in optional)
    #         else:
    #             optional_arguments = ""
    #         raise InvalidArgumentError(f"Invalid input format. Expected arguments: {expected_arguments}{optional_arguments}")
        
    #     if len(input_args) > len(args):
    #         if len(args) == 0 or args[-1].type != str:
    #             raise InvalidArgumentError(f"Too many arguments. Expected {len(args)} but got {len(input_args)}")
    #         else:
    #             # If the last argument is a string, join the remaining input into a single string and remove the rest
    #             input_args[len(args)-1] = ' '.join(input_args[len(args) - 1:])
    #             input_args = input_args[:len(args)]

    #     # Map argument names to parsed values
    #     parsed_args_list = []
    #     for arg_spec, arg_value in zip(args, input_args):
    #         if arg_value is None:
    #             break # must be because of optional arguments
    #         # Convert the argument value to the specified type
    #         parsed_args_list.append(convert_argument(arg_spec.type, arg_value))

    #     # If there's remaining input, join it into a single string and assign it to the last argument
    #     if len(parsed_args_list) < len(required):
    #         if not args[-1][1] == str:
    #             raise InvalidArgumentError(f"Failed to convert argument '{required[-1].name}' to type '{required[-1].type.__name__}' from '{parsed_args_list[-1]}{' '.join(parsed_args[len(required) - 1:])}'")
    #         parsed_args_list.append(' '.join(parsed_args[len(required) - 1:]))
    #     return parsed_args_list

    async def run(self, check_until:Callable[[angr.SimulationManager],StopReason] = lambda _:StopReason.NONE, exclude:Callable[[angr.SimState],bool] = lambda _:False):
        u = check_until
        exclusions = self.exclusions
        def check(simgr:angr.SimulationManager):
            r = u(simgr)
            if r != StopReason.NONE:
                return r
            state = simgr.one_active
            if self.trigger_points.filter(state):
                return StopReason.BREAKPOINT
            return StopReason.NONE

        def _exclude(state:angr.SimState)->bool:
            if exclude(state):
                return True
            return any([f.filter(state) for f in exclusions])
        
        await self._run(self, check,_exclude)