from abc import abstractmethod
import inspect
from typing import Callable, cast
from angr import SimulationManager
from claripy import List

from dAngr.angr_ext.debugger import Debugger
from dAngr.angr_ext.step_handler import StopReason
from dAngr.exceptions import ExecutionError
from dAngr.utils.utils import ArgumentSpec, convert_args, parse_docstring, undefined

# def get_cmd_name(cls):
#     return ''.join(['_'+i.lower() if i.isupper() else i for i in cls.__name__.replace('Command', '')]).lstrip('_')

def get_short_cmd_name(name):
    # use the first letter of each word in the command name
    return ''.join([i.lower() for i in name if i.isupper()])

class AutoRunMeta(type):
    def __init__(cls_, name, bases, dct):
        super().__init__(name, bases, dct)
        # Automatically trigger the static method
        if hasattr(cls_, '__render_commands__'):
            cls_.__render_commands__(cls_) # type: ignore

class IBaseCommand(metaclass=AutoRunMeta):
    def __init__(self, debugger:Debugger):
        self._debugger = debugger
    
    def cmd_specs(self):
        return getattr(self.__class__, "__cmd_specs__", {})
    
    def get_cmd_specs(self, command:str):
        specs = self.cmd_specs()
        return next((specs[s] for s in specs if specs[s].name.strip() == command or specs[s].short_name == command), None)
    
    @abstractmethod
    async def execute(self, cmd, *args):
        pass

class CommandSpec:
    def __init__(self, cmd:type[IBaseCommand], name:str, func:Callable, description:str, args:list, short_name:str, example:str, package:str): 
        self.cmd = cmd
        self.package = package
        self.name = name
        self.func = func
        self.description = description
        self.args = args
        self.short_name = short_name
        self.example = example
    def get_required_args(self) -> List[ArgumentSpec]:
        return [a for a in self.args if a.default == undefined]
    
    def get_optional_args(self)-> List[ArgumentSpec]:
        return [a for a in self.args if a.default != undefined]
    def __str__(self):
        return f"{self.name} - {self.description}"
    
    def execute(self, debugger:Debugger, *args):
        # call func with the debugger and the arguments
        o = self.cmd(debugger)
        # get the function from the class
        f = getattr(o, self.name, None)
        if not f:
            f = getattr(o, self.name + '_')
        return f(*args)

class BaseCommand(IBaseCommand, metaclass=AutoRunMeta):


    @staticmethod
    def __render_commands__(base_class):
        # through reflection get each function from the class
        # if the function is public, add it as a command
        if not issubclass(base_class, __class__) or base_class == __class__:
            return

        def check(func):
            if inspect.isfunction(func):
                if func.__name__.startswith('_') or func.__name__ == 'cmd_specs':
                    return False
                # check if the function is from the derived class
                if func.__qualname__.split('.')[0] == base_class.__name__:
                    return True
            return False
        functions = inspect.getmembers(base_class, predicate=check)
        specs = []
        for name, fun in functions:
            name = name.strip('_')
            if name == 'execute':
                raise ValueError("Function name 'execute' is reserved.")
            doc = fun.__doc__
            if not doc:
                raise ValueError(f"Function {name} does not have a docstring")
            #parse the docstring
            info = parse_docstring(doc)
            args = convert_args(info["args"], signature=inspect.signature(fun))
            package = base_class.__module__.split('.')[-1]
            #parse the arguments
            specs.append(CommandSpec(base_class, name, fun, info["description"], args, info["short_name"], info["extra_info"], package))
        setattr(base_class, "__cmd_specs__", {s.name: s for s in specs})
        # args = []
        # oargs = []
        # named_args = decorator_kwargs
        # # check if args are optional
        # signature = inspect.signature(fun)
        # for arg in named_args:
        #     if arg == "short_name":
        #         continue
        #     par_description = named_args[arg]
        #     if arg not in signature.parameters:
        #         raise ValueError(f"Function {fun.__name__} does not have a parameter named {arg}")
        #     t = signature.parameters[arg].annotation
        #     d = signature.parameters[arg].default
        #     if not d is inspect._empty:
        #         oargs.append((arg,t,par_description,d))
        #     else:
        #         if oargs:
        #             raise ValueError("Optional arguments must come after required arguments")
        #         args.append((arg,t,par_description))
        # name = fun.__name__.strip('_')
        # short_cmd_name = named_args.get("short_name", get_short_cmd_name(name))
        # BaseCommand.cmd_specs.append({"name": name, "func":fun, "description": description, "args":args, "optional":oargs, short_cmd_name: short_cmd_name, "extra_info": extra_info})


    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.paused = False


    @property
    def debugger(self):
        from dAngr.cli.command_line_debugger import CommandLineDebugger

        if self._debugger is None:
            raise ExecutionError("Debugger not set.")
        # return self._debugger
        return cast(CommandLineDebugger,self._debugger)


    async def run_angr(self, until:Callable[[SimulationManager],StopReason] = lambda _: StopReason.NONE):
        u = until
        await self.debugger.run(u)

    # def get_example(self):
    #     args_lst = [f"<{a[0].replace(' ','_')}>"  for a in self.arg_specs]
    #     options = [f"<{a[0].replace(' ','_')}>"  for a in self.optional_args]
    #     args = ''
    #     if args_lst:
    #         args = ', '.join(args_lst)
    #     if args and options:
    #         args += ', ['
    #         args += ', '.join(options)
    #         args += ']'
    #     if args:
    #         args = " " + args  
    #         return f"{get_cmd_name(self.__class__)}{args}"
    #     else:
    #         return None
    
    def send_info(self, data):
        return self.debugger.conn.send_info(data)

    def send_error(self, data):
        return self.debugger.conn.send_error(data)
    
    def send_warning(self, data):
        return self.debugger.conn.send_warning(data)
    
    def send_result(self, data):
        return self.debugger.conn.send_result(data)
    

    