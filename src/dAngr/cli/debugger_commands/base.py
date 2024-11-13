from abc import abstractmethod
import inspect
from typing import Any, Callable, cast, get_args
from angr import SimulationManager
from claripy import List

from dAngr.angr_ext.debugger import Debugger
from dAngr.angr_ext.step_handler import StopReason
from dAngr.cli.grammar.definitions import ArgumentSpec, FunctionDefinition
from dAngr.cli.grammar.execution_context import Variable
from dAngr.exceptions import ExecutionError, InvalidArgumentError,DebuggerCommandError
from dAngr.utils.utils import str_to_type, undefined, AngrExtendedType, AngrType, AngrValueType, StreamType, DataType, ObjectStore, SymBitVector, Constraint

# required for str_to_type - do not remove
from dAngr.cli.grammar.expressions import *




# def get_cmd_name(cls):
#     return ''.join(['_'+i.lower() if i.isupper() else i for i in cls.__name__.replace('Command', '')]).lstrip('_')

def get_short_cmd_name(name):
    # use the first letter of each word in the command name
    return ''.join([i.lower() for i in name if i.isupper()])

class AutoRunMeta(type):
    def __init__(self, name, bases, dct):
        super().__init__(name, bases, dct)
        # Automatically trigger the static method
        if hasattr(self, '__render_commands__'):
            self.__render_commands__(self) # type: ignore

class IBaseCommand(metaclass=AutoRunMeta):
    def __init__(self, debugger:Debugger):
        self._debugger = debugger
    
    def cmd_specs(self):
        return getattr(self.__class__, "__cmd_specs__", {})
    
    def get_cmd_specs(self, command:str):
        specs = self.cmd_specs()
        return next((specs[s] for s in specs if specs[s].name.strip() == command or specs[s].short_name == command), None)
    
    @abstractmethod
    def execute(self, cmd, *args):
        pass



class BuiltinFunctionDefinition(FunctionDefinition):
    def __init__(self, name:str, cmd_class:type[IBaseCommand], func: Callable,  description:str, args:List[ArgumentSpec], short_name:str, example:str, package:str):
        super().__init__(name, package, args)
        self._cmd_class = cmd_class
        self._func = func
        self._description = description
        self._short_name = short_name
        self._example = example
        self._package = package
    @property
    def name(self):
        return self._name
    @property
    def func(self):
        return self._func
    @property
    def cmd_class(self):
        return self._cmd_class
    @property
    def description(self):
        return self._description
    @property
    def short_name(self):
        return self._short_name
    @property
    def example(self):
        return self._example
    @property
    def package(self):
        return self._package
    
    def __call__(self, context:ExecutionContext,*args, **named_args) -> Any:
        from dAngr.cli.command_line_debugger import dAngrExecutionContext
        o = self._cmd_class(cast(dAngrExecutionContext,context.root).debugger)
        # get the function from the class
        f = getattr(o, self._name, None)
        if not f:
            f = getattr(o, self._name + '_')

        return f(*args, **named_args)
    
def convert_args(args, signature):
    # convert the args to the correct type
    pargs = []
    for name in args:
        a = signature.parameters.get(name)
        if not a:
            raise InvalidArgumentError(f"Function {signature} does not have a parameter named {name}")
        arg = args[name]
        tp = arg["type"]
        #check if the type matches the function definitions arg type
        if a.kind == inspect.Parameter.VAR_POSITIONAL:
            if tp != tuple:
                raise InvalidArgumentError(f"Function {signature} parameter {name} has type {a.annotation} but expected {tp}")
            else:
                # get the type of the elements in the tuple
                pargs.append(ArgumentSpec(name, tp, undefined, arg["description"]))
        elif a.kind == inspect.Parameter.VAR_KEYWORD:
            if tp != dict:
                raise InvalidArgumentError(f"Function {signature} parameter {name} has type {a.annotation} but expected {tp}")
            else:
                # get the type of the elements in the tuple
                pargs.append(ArgumentSpec(name, tp, undefined, arg["description"]))
        else:
            if tp is None:
                tp = inspect._empty
                # raise InvalidArgumentError(f"Function {signature} parameter {name} does not have a type annotation")
            if tp != a.annotation:
                # check if the type is a union
                if not (tp in get_args(a.annotation)):
                    raise InvalidArgumentError(f"Function {signature} parameter {name} has type {a.annotation} but expected {tp}")
            description = arg["description"]
            default = a.default if a.default != inspect._empty else undefined
            pargs.append(ArgumentSpec(name,tp, default, description))  # type: ignore
    return pargs


def parse_docstring(docstring:str):
    # parse the description, args, short name, and extra info, return value from the docstring, Don't care about the errors raised
    description = ""
    args = []
    example = ""
    short_name = ""
    return_value = ""

    state = 0
    if docstring:
        lines = docstring.split("\n")
        description = lines[0]
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("args:"):
                state = 1
                if line.endswith(":"):
                    continue
            elif line.lower().startswith("short name:"):
                if line.endswith(":"):
                    continue
                state = 2
            elif line.lower().startswith("returns:"):
                state = 3
                if line.endswith(":"):
                    continue
            elif line.lower().startswith("raises:"):
                state = 4
                if line.endswith(":"):
                    continue
            elif line.lower().startswith("example:"):
                state = 5
                if line.endswith(":"):
                    continue
            if state == 0:
                description += line
            elif state == 1:
                args.append(line)
            elif state == 2:
                short_name = '/' + line.split(":")[1].strip()
            elif state == 3:
                return_value = line
            elif state == 4:
                # parse the raises
                pass
            if state == 5:
                example += line
    args = parse_args(args)

    return {"description":description, "args":args, "short_name":short_name, "example":example, "return_value":return_value}



def parse_args(args):
    # parse the args
    parsed_args = {}
    for arg in args:
        arg = arg.strip()
        if arg:
            if ":" in arg:
                name_type, description = arg.split(":", 1)
                name, dtype = name_type.strip().split(' ')
                dtype = dtype.strip('(').strip(')').strip()
                #convert string dtype to typings type
                tp = str_to_type(dtype)
                parsed_args[name] = {"type":tp, "description":description.strip()}
            else:
                # TODO add multiline support
                raise InvalidArgumentError(f"Invalid argument specification: {arg}")  
    return parsed_args


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
                raise DebuggerCommandError("Function name 'execute' is reserved.")
            doc = fun.__doc__
            if not doc:
                raise DebuggerCommandError(f"Function {name} does not have a docstring")
            #parse the docstring
            info = parse_docstring(doc)
            args = convert_args(info["args"], signature=inspect.signature(fun))
            package = base_class.__module__.split('.')[-1]
            #parse the arguments
            specs.append(BuiltinFunctionDefinition(name,base_class, fun, info["description"], args, info["short_name"], info["example"], package))
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
    
    def to_value(self, value: int|bytes|str|SymBitVector|Variable):
        if value is None:
            return None
        if isinstance(value, Variable):
            return value.value
        return value
    
    def get_angr_value(self, ref:AngrType)->AngrValueType:
        if isinstance(ref, str):
            var = self.debugger.context.find_variable(ref)
            if var:
                assert isinstance(var.value, AngrValueType), f"Invalid value type {type(var.value)}"
                return var.value
            else:
                sym = self.debugger.find_symbol(ref)
                if not sym is None:
                    return sym
                else:
                    log.debug(f"Variable or symbol {ref} not found, asuming string conversion.")
                    return ref
        elif isinstance(ref, Variable):
            return ref.value # type: ignore
        else:
            return ref

    def run_angr(self, until:Callable[[SimulationManager],StopReason] = lambda _: StopReason.NONE):
        u = until
        self.debugger.run(u)

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
    
    def send_result(self, data, newline = True):
        return self.debugger.conn.send_result(data, newline)
    

    