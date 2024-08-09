from abc import abstractmethod
from typing import Callable, cast
from angr import SimState, SimulationManager
from dAngr.angr_ext import utils
from dAngr.angr_ext.debugger import Debugger
from dAngr.angr_ext.step_handler import StepHandler, StopReason
from dAngr.exceptions import ExecutionError

def get_cmd_name(cls):
    return ''.join(['_'+i.lower() if i.isupper() else i for i in cls.__name__.replace('Command', '')]).lstrip('_')

def get_short_cmd_name(cls):
    # use the first letter of each word in the command name
    return ''.join([i.lower() for i in cls.__name__.replace('Command', '') if i.isupper()])

class BaseCommand(StepHandler):
    def __init__(self, debugger:Debugger|None):
        self._debugger = debugger
        self.arg_specs = []
        self.optional_args = []
        self.info = ""
        self.paused = False
        self.cmd_name = get_cmd_name(self.__class__)
        self.short_cmd_name = get_short_cmd_name(self.__class__)
        self.extra_info = ""


    @property
    def debugger(self):
        from dAngr.cli.command_line_debugger import CommandLineDebugger

        if self._debugger is None:
            raise ExecutionError("Debugger not set.")
        # return self._debugger
        return cast(CommandLineDebugger,self._debugger)

    async def execute_base(self, *args):
        return await self.execute(*args)

    @abstractmethod
    async def execute(self, args):
        raise NotImplementedError("Each command must implement an execute method")

    async def run(self, until:Callable[[SimulationManager],StopReason] = lambda _: StopReason.NONE):
        u = until
        await self.debugger.run(u)

    def get_example(self):
        args_lst = [f"<{a[0].replace(' ','_')}>"  for a in self.arg_specs]
        options = [f"<{a[0].replace(' ','_')}>"  for a in self.optional_args]
        args = ''
        if args_lst:
            args = ', '.join(args_lst)
        if args and options:
            args += ', ['
            args += ', '.join(options)
            args += ']'
        if args:
            args = " " + args  
            return f"{get_cmd_name(self.__class__)}{args}"
        else:
            return None
    
    def send_info(self, data):
        return self.debugger.conn.send_info(data)

    def send_error(self, data):
        return self.debugger.conn.send_error(data)
    
    def send_warning(self, data):
        return self.debugger.conn.send_warning(data)
    
    def send_result(self, data):
        return self.debugger.conn.send_result(data)
    

    