from enum import Enum
import io
from types import UnionType
from typing import Dict, List, Any, Union, cast, get_args, get_origin
from abc import abstractmethod
import subprocess
import claripy

from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.exceptions import CommandError, InvalidArgumentError, ValueError, KeyError
from dAngr.utils import AngrValueType, StreamType, str_to_address
from dAngr.utils.utils import DataType, Endness, check_signature_matches
from contextlib import redirect_stdout, redirect_stderr

from dAngr.utils.loggers import get_logger
log = get_logger(__name__)

class Expression:
    def debugger(self, context):
        from dAngr.cli.command_line_debugger import CommandLineDebugger
        return cast(CommandLineDebugger, context.root.debugger)

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
        return self.debugger(context).get_symbol(self.name)
    
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
        self.debugger(context).set_memory(self.address, value, None,Endness.DEFAULT)
    
    def __str__(self):
        return f"&mem[{hex(self.address)}->{self.size}]"
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
    
class StateObject(ReferenceObject):
    def __init__(self):
        super().__init__("state")
    def get_value(self, context):
        return self.debugger(context).current_state
    def set_value(self, context, value):
        raise ValueError("Cannot set value to a state object")
    def __str__(self):
        return f"&state"
    def __eq__(self, other):
        return isinstance(other, StateObject)

class VariableRef(ReferenceObject):
    def __init__(self, name:str, is_static=False):
        self.name = name
        self._is_static = is_static
    
    @property
    def is_static(self):
        return self._is_static
    @property
    def static_name(self):
        if not self._is_static:
            raise ValueError(f"Variable {self.name} is not static")
        return f"@{self.name}"
    
    def __str__(self):
        return f"{self.name}"

    def __eq__(self, other):
        return isinstance(other, VariableRef) and self.name == other.name
    
    def get_value(self, context):
        return context[self.name].value
    def set_value(self, context, value):
        assert isinstance(value,AngrValueType)
        context[self.name] = value

class Property(ReferenceObject):
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
    
class Constraint(Expression):
    pass
class IfConstraint(Constraint):
    def __init__(self, condition:Expression, true_constraint:Constraint, false_constraint:Constraint):
        self.condition = condition
        self.true_constraint = true_constraint
        self.false_constraint = false_constraint

    async def __call__(self, context:ExecutionContext):
        cthen =  await self.true_constraint(context)
        if not isinstance(cthen, claripy.ast.Base):
            cthen = await self.debugger(context).render_argument(cthen,False)
        celse = await self.false_constraint(context)
        if not isinstance(celse, claripy.ast.Base):
            celse = await self.debugger(context).render_argument(celse,False)
        return claripy.If(await self.condition(context), cthen, celse)
    
    def __str__(self):
        return f"if {self.condition} then {self.true_constraint} else {self.false_constraint}"
    
    def __eq__(self, value: object) -> bool:
        return isinstance(value, IfConstraint) and self.condition == value.condition and self.true_constraint == value.true_constraint and self.false_constraint == value.false_constraint
    
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

    async def _to_val(self, arg, context:ExecutionContext):
        v = await arg(context)
        if isinstance(arg, ReferenceObject):
            if isinstance(v, str) or isinstance(v, bytes):
                return repr(v)
        if isinstance(v, claripy.ast.BV):
            return repr(self.debugger(context).cast_to(v, DataType.str))
        return v
    
    async def __call__(self, context:ExecutionContext):
        # copy the commands locally
        # execute the commands if it is an Expression and replace the entry in the copy with the result
        c = context.clone()
        results = [await self._to_val(a,c) for a in self.cmds] + [f"{k}={await v(c)}" for k,v in self.kwargs.items()]
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                cmd = "".join([str(r) for r in results])
                context.return_value = eval(cmd)
            except Exception as e:
                raise CommandError(f"Error executing python command: {cmd} ({e})")
        if stdout := stdout_buffer.getvalue():
            await self.debugger(context).conn.send_output(stdout)
        if stderr := stderr_buffer.getvalue():
            await self.debugger(context).conn.send_error(stderr)
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

    async def _check_arg(self, arg, context:ExecutionContext, spec):
        try:
            #TODO, what if  dtype is a tuple
            if isinstance(spec.dtype, type) and issubclass(spec.dtype, ReferenceObject):
                return arg
            elif isinstance(spec.dtype, type) and issubclass(spec.dtype,Enum):
                return spec.dtype[arg.name]
            else:
                return await arg(context) 
        except KeyError as e:
            if "Unknown variable: " in e.args[0]:
                # if dtype is a typle, get list of types
                # check if dtype is a tuple
                if get_origin(spec.dtype) is UnionType:
                    types = get_args(spec.dtype)
                else:
                    types = [spec.dtype]
 
                if isinstance(arg, VariableRef) and (str in types or Enum in types):
                    for t in types:
                        if issubclass(t, Enum):
                            if arg.name in t.__members__: # type: ignore
                                return t[arg.name] # type: ignore
                    if str in types:
                        return arg.name
                log.debug(f"{arg.name} not found in variables, using value as is")
                return arg.name
            else:
                raise e
        

    async def __call__(self, context:ExecutionContext):
        from dAngr.cli.command_line_debugger import BuiltinFunctionDefinition
        spec = None
        if self.cmd in context.functions :
            spec = context.functions[self.cmd]
        elif self.cmd in [f.short_name for f in context.functions.values() if isinstance(f, BuiltinFunctionDefinition)]:
            spec = next((f for f in context.functions.values() if cast(BuiltinFunctionDefinition,f).short_name == self.cmd), None)
        if not spec:
            if context.find_variable(self.cmd):
                return context[self.cmd].value
            else:
                raise CommandError(f"Unknown command: {self.cmd}")
        s_args = spec.args
        if len(spec.args) < len(self.args):
            if spec.args and  spec.args[-1].dtype == tuple:
                # copy the last argument until there are enough arguments
                while len(s_args) < len(self.args):
                    s_args.append(s_args[-1])
            else:
                raise CommandError(f"Too many arguments. Expected {len(spec.args)} but got {len(self.args)}")
        spec = cast(BuiltinFunctionDefinition, spec)
        func = spec.func
        arguments = [ await self._check_arg(arg, context, s_args[i]) for i,arg in enumerate(self.args) ]
        named_args = {k: await self._check_arg(v,context, spec.get_arg_by_name(k)) for k,v in self.kwargs.items()}   
        # self._check_args(arguments, named_args, spec)

        check_signature_matches(func, spec, arguments, named_args)
        log.debug(lambda:f"Calling {self.cmd} with {arguments} {named_args}")
        context.return_value = await spec(context, *arguments, **named_args)
        return context.return_value

            

    def __str__(self):
        return f"{self.cmd} {[str(a) for a in self.args]}"
    def __eq__(self, other):
        return isinstance(other, DangrCommand) and self.cmd == other.cmd and self.args == other.args and self.kwargs == other.kwargs

    