from enum import Enum
import logging
from typing import Dict, List, Any, cast
from abc import abstractmethod
import subprocess
import claripy

from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.exceptions import CommandError, InvalidArgumentError, ValueError, KeyError
from dAngr.utils import AngrValueType, StreamType, str_to_address
from dAngr.utils.utils import check_signature_matches

log = logging.getLogger(__name__)

class Expression:
    def debugger(self, context):
        from dAngr.cli.command_line_debugger import CommandLineDebugger

        return cast(CommandLineDebugger, context.debugger)

    @abstractmethod
    async def __call__(self, context:ExecutionContext):
        raise NotImplementedError
    
    @staticmethod
    def toBool(v):
        if v is None:
            return False
        if isinstance(v, bool):
            return v
        elif isinstance(v, str):
            return v != ""
        elif isinstance(v, list):
            return len(v) > 0
        elif not v is None:
            if isinstance(v, int):
                return v > 0
            else:
                return True
        return False
        

    def __repr__(self):
        # class name followed by __str__
        return f"{self.__class__.__name__}({self.__str__()})"

    @abstractmethod
    def __str__(self):
        raise NotImplementedError    
    @abstractmethod
    def __eq__(self, other):
        raise NotImplementedError
    @abstractmethod
    def __hash__(self):
        return hash(self.__repr__())

class Object(Expression):
    # a symbol is a variable, argument, constant, memory, register, or stream
    async def __call__(self, context: ExecutionContext):
        return self.get_value(context)
    @abstractmethod
    def get_value(self, context)-> Any:
        raise NotImplementedError  
    @abstractmethod
    def set_value(self, context, value:Any):
        raise NotImplementedError
    
class Primitive(Object):
    pass

class Literal(Primitive):
    def __init__(self, value):
        self.value = value
        
    def get_value(self, context):
        return self.value
    
    def set_value(self, context, value):
        raise ValueError("Cannot set value to a literal object")
    
    def __str__(self):
        return f"{self.value}"
    
    def __eq__(self, other):
        return isinstance(other,Literal) and self.value == other.value

class Iterable():
    def __iter__(self):
        raise NotImplementedError
    def __get_item__(self, index):
        raise NotImplementedError
    def __set_item__(self, index, value):
        raise NotImplementedError
class Range(Primitive,Iterable):
    def __init__(self, start:int, end:int=-1):
        self.start = start
        self.end = end
    def __str__(self):
        if self.end == -1:
            return f"range({self.start})"
        else:
            return f"range({self.start},{self.end})"
    def __iter__(self):
        if self.end == -1:
            return iter(range(self.start))
        else:
            return iter(range(self.start, self.end))

    def __eq__(self, other):
        return isinstance(other, Range) and self.start == other.start and self.end == other.end
    
    def get_value(self, context):
        return list(self)
    def set_value(self, context, value):
        raise ValueError("Cannot set value to a range object")
    
class Listing(Primitive,Iterable):
    def __init__(self, items:List[Object]):
        self.items = items

    def __str__(self):
        return f"{self.items}"
    
    def __eq__(self, other):
        return isinstance(other, Listing) and self.items == other.items
    
    def __iter__(self):
        return self.items.__iter__()

    def get_value(self, context):
        return [i.get_value(context) for i in self.items]
    
    def set_value(self, context, value: list):
        for i, v in enumerate(value):
            self.items[i].set_value(context, v)

class Dictionary(Primitive,Iterable):
    def __init__(self, items:Dict[str,Object]):
        self.items = items

    def __str__(self):
        return '{' + ", ".join([f"{k}:{v}" for k,v in self.items.items()]) + '}'
    def __eq__(self, other):
        return isinstance(other, Dictionary) and self.items == other.items
    
    def get_value(self, context):
        return {k:v.get_value(context) for k,v in self.items.items()}
    
    def set_value(self, context, value: dict):
        for k, v in value.items():
            self.items[k].set_value(context, v)
#Reference Objects
class ReferenceObject(Object):

    def __init__(self, name:str):
        self.name = name

    @staticmethod
    def createNamedObject(db:str, name:str):
        switcher = {
            "&reg": Register,
            "&sym": SymbolicValue,
            "&io": Stream,
            "&vars": VariableRef
        }
        return switcher.get(db,None)(name)
        
        
class Stream(ReferenceObject):
    def __init__(self, stream:StreamType):
        super().__init__(f"{stream}")
        self.stream = stream
    def __str__(self):
        return f"&io.{self.stream}"
    def get_value(self, context):
        return self.debugger(context).get_stream(self.stream)
    def set_value(self, context, value):
        raise ValueError("Cannot set value to a stream object")
    def __eq__(self, other):
        return isinstance(other, Stream) and self.stream == other.stream

class SymbolicValue(ReferenceObject):
    def __init__(self, name):
        super().__init__(name)

    def get_value(self, context):
        #get variable value and 
        return self.debugger(context).get_symbol_value(self.name)
    
    def set_value(self, context, value):
        assert isinstance(value,AngrValueType)
        self.debugger(context).set_symbol(self.name, value)

    def __str__(self):
        return f"&sym.{self.name}"
    def __eq__(self, other):
        return isinstance(other, SymbolicValue) and self.name == other.name
    
class Memory(ReferenceObject):
    def __init__(self, address:int, size:int):
        super().__init__(f"{address}->{size}")
        self.address = address
        self.size = size 

    def get_value(self, context):
        return self.debugger(context).get_memory(self.address, self.size)

    def set_value(self, context, value):
        assert isinstance(value,AngrValueType)
        self.debugger(context).set_memory(self.address, value)
    
    def __str__(self):
        return f"&mem.{self.address}->{self.size}"
    def __eq__(self, other):
        return isinstance(other, Memory) and self.address == other.address and self.size == other.size
    
class Register(ReferenceObject):
    def __init__(self, name):
        self.name = name

    @property
    def register(self):
        return self.name
    def get_value(self, context):
        return self.debugger(context).get_register(self.register)
    
    def set_value(self, context, value):
        if isinstance(value, int) or isinstance(value, claripy.ast.BV):
            self.debugger(context).set_register(self.register, value)
        else:
            raise ValueError(f"Invalid value type: {value}")    
    def __str__(self):
        return f"&reg.{self.register}"
    def __eq__(self, other):
        return isinstance(other, Register) and self.register == other.register

class VariableRef(ReferenceObject):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return f"&vars.{self.name}"

    def __eq__(self, other):
        return isinstance(other, VariableRef) and self.name == other.name
    
    def get_value(self, context):
        return context[self.name]
    def set_value(self, context, value):
        context[self.name] = value

class Property(VariableRef):
    def __init__(self, obj:Object, prop):
        super().__init__(f"{obj}.{prop}")
        self.obj = obj
        self.prop = prop

    def __str__(self):
        return f"{self.obj}.{self.prop}"
    def __eq__(self, other):
        return isinstance(other, Property) and self.prop == other.prop
    
    def set_value(self, context, value: Any):
        o = self.obj.get_value(context) 
        if hasattr(o, self.prop):
            setattr(o, self.prop, value)
        else:
            raise InvalidArgumentError(f"Object {o} does not have property {self.prop}")
    def get_value(self, context):
        o = self.obj.get_value(context)
        if hasattr(o, self.prop):
            return getattr(o, self.prop)
        else:
            raise InvalidArgumentError(f"Object {o} does not have property {self.prop}")
        
class IndexedProperty(Property):
    def __init__(self, obj:Object, index):
        super().__init__(obj, index)

    @property
    def index(self):
        return self.prop
    
    def __str__(self):
        return f"{self.obj}[{self.index}]"
    
    def set_value(self, context, value: Any):
        o = self.obj.get_value(context)
        if isinstance(o, list):
            o[self.index] = value
        else:
            raise InvalidArgumentError(f"Object {o} does not support indexing")
    def get_value(self, context):
        o = self.obj.get_value(context)
        if isinstance(o, list):
            return o[self.index]
        else:
            raise InvalidArgumentError(f"Object {o} does not support indexing")

class Slice(Property):
    def __init__(self, obj:Object, start:int, end:int):
        super().__init__(obj, f"{start}:{end}")
        self.start = start
        self.end = end
    @property
    def size(self):
        return self.end - self.start
    
    def get_value(self, context):
        return super().get_value(context)[self.start:self.end]
    
    def set_value(self, context, value: list):
        o = self.obj.get_value(context)
        if isinstance(value, list):
            o[self.start:self.end] = value
        else:
            raise InvalidArgumentError(f"Object {o} does not support slicing")
    def __str__(self):
        return f"{self.obj}[{self.start}:{self.end}]"
    def __eq__(self, other):
        return isinstance(other, Slice) and self.start == other.start and self.end == other.end
class Comparison(Expression):
    def __init__(self, left:Expression, operator, right:Expression):
        self.left = left
        self.operator = operator
        self.right = right

    async def __call__(self, context:ExecutionContext):
        left = await self.left(context)
        right = await self.right(context)
        return getattr(left, self.operator)(right)
    
    def __str__(self):
        return f"{self.left}{self.operator}{self.right}"
    
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Comparison) and self.left == value.left and self.operator == value.operator and self.right == value.right


class Command(Expression):
    def _merge_consecutive_literals(self, content:List[Literal|Expression]) ->List[Expression]:
        cc = []
        for c in content:
            if cc and isinstance(cc[-1], Literal) and isinstance(c, Literal):
                cc[-1] = Literal(cc[-1].value + str(c.value))
            else:
                cc.append(c)
        return cc
    @abstractmethod
    async def __call__(self, context):
        raise NotImplementedError

class PythonCommand(Command):
    def __init__(self, *cmds:Expression|str|int|bytes, **kwargs:Expression):
        cc = [ Literal(c) if isinstance(c, (str,int,bytes)) else c for c in cmds if isinstance(c, (Expression,str,int,bytes))]
        self.cmds:List[Expression] = self._merge_consecutive_literals(cc)
        self.kwargs:Dict[str,Expression] = kwargs

    
    async def __call__(self, context:ExecutionContext):
        # copy the commands locally
        # execute the commands if it is an Expression and replace the entry in the copy with the result
        c = context.clone()
        results = [await a(c) for a in self.cmds] + [f"{k}={await v(c)}" for k,v in self.kwargs.items()]
        context.return_value = await eval(" ".join(results))
        return context.return_value
    
    def __str__(self):
        return "".join([ str(c) for c in self.cmds])
    def __eq__(self, other):
        return isinstance(other, PythonCommand) and self.cmds == other.cmds
    
class BashCommand(Command):
    def __init__(self, *cmds:Expression|str|int|bytes):
        cc = [ Literal(c) if isinstance(c, (str,int,bytes)) else c for c in cmds if isinstance(c, (Expression,str,int,bytes))]
        self.cmds:List[Expression] = self._merge_consecutive_literals(cc)

    async def __call__(self, context):
        c = context.clone()
        results = [await a(c) for a in self.cmds]
        context.return_value = subprocess.run(" ".join(results), capture_output=True, text=True).stdout.strip()
        return context.return_value
    
    def __str__(self):
        return "".join([ str(c) for c in self.cmds])
    def __eq__(self, other):
        return isinstance(other, BashCommand) and self.cmds == other.cmds
         
class DangrCommand(Command):
    def __init__(self, cmd:str, *args:Expression, **kwargs:Expression):
        self.cmd = cmd
        self.args:List[Expression] = [*args]
        self.kwargs:Dict[str,Expression] = kwargs

    # async def _collapse_args(self, args:List[Expression], spec):
    #     args = self.args
    #     if spec.args[-1].dtype == str:
    #         size = len(spec.args)
    #         # replace varables and collapse the last arguments into a single string
    #         cst = CompoundExpression(args[size-1:])
    #         args = args[:size-1] + [cst]
    #     return args
    # def _check_args(self, args, kwargs, spec):
    #     # for each unnamed argument check types:
    #     # note, if type is Identifier, 

    #     if len(args) < len(spec.required_arguments):
    #         raise InvalidArgumentError(f"Missing required arguments: {spec.required_arguments}")
    #     if len(args) > len(spec.args):
    #         raise InvalidArgumentError(f"Too many arguments: {args}")
    #     for i, arg in enumerate(args):
    #         if (isinstance(arg, tuple)):
    #             if i < len(spec.required_arguments):
    #                 raise InvalidArgumentError(f"Invalid argument: {arg} expected {spec.args[i].dtype}")
    #             # all remaining args must be named args
    #             for i in range(i, len(args)):
    #                 if not args[i][0] in [a.name for a in spec.args]:
    #                     raise InvalidArgumentError(f"Unknown argument: {args[i][0]}")
    #         else:
    #             if not isinstance(arg, spec.args[i].dtype):
    #                 raise InvalidArgumentError(f"Invalid argument type: {arg} expected {spec.args[i].dtype}")
    async def _check_arg(self, arg, context:ExecutionContext, spec):
        try:
            return await arg(context) 
        except KeyError as e:
            if "Unknown variable: " in e.args[0]:
                if isinstance(spec.dtype, (str,Enum)):
                    return arg.name
                log.info(f"{arg.name} not found in variables, using value as is")
                return arg.name
            else:
                raise e
        

    async def __call__(self, context:ExecutionContext):
        from dAngr.cli.command_line_debugger import BuiltinFunctionDefinition
        if self.cmd in context.functions:
            spec = cast(BuiltinFunctionDefinition,context.functions[self.cmd])
            if len(spec.args) < len(self.args):
                raise CommandError(f"Too many arguments. Expected {len(spec.args)} but got {len(self.args)}")
            func = spec.func
            arguments = [ await self._check_arg(arg, context, spec.args[i]) for i,arg in enumerate(self.args) ]
            named_args = {k: await self._check_arg(v,context, spec.get_arg_by_name(k)) for k,v in self.kwargs.items()}   
            # self._check_args(arguments, named_args, spec)
            o = context.definitions[self.cmd]
            check_signature_matches(func, o, arguments, named_args)     
            context.return_value = await o(context, *arguments, **named_args)
            return context.return_value
        else:
            raise CommandError(f"Unknown dAngr command: {self.cmd}")

    def __str__(self):
        return f"{self.cmd} {[str(a) for a in self.args]}"
    def __eq__(self, other):
        return isinstance(other, DangrCommand) and self.cmd == other.cmd and self.args == other.args and self.kwargs == other.kwargs

    