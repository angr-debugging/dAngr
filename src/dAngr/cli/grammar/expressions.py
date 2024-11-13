from enum import Enum, auto
import io
from types import UnionType
from typing import Dict, List, Any, Union, cast, get_args, get_origin
from abc import abstractmethod
import subprocess
import claripy

from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.exceptions import CommandError, DebuggerCommandError, InvalidArgumentError, ValueError, KeyError
from dAngr.utils import AngrValueType, AngrExtendedType, StreamType, str_to_address
from dAngr.utils.utils import DataType, Endness, Operator, check_signature_matches, is_indexable
from contextlib import redirect_stdout, redirect_stderr

from dAngr.utils.loggers import get_logger
log = get_logger(__name__)



class Expression:
    def debugger(self, context):
        from dAngr.cli.command_line_debugger import CommandLineDebugger
        return cast(CommandLineDebugger, context.root.debugger)

    @abstractmethod
    def __call__(self, context:ExecutionContext):
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
    def __call__(self, context: ExecutionContext):
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
    
    def __repr__(self):
        return self.__str__()
    
    def __eq__(self, other):
        return isinstance(other,Literal) and self.value == other.value


class Range(Primitive):
    def __init__(self, start:Expression, end:Expression|None=None, step:Expression|None=None):
        self.start = start
        self.end = end
        self.step = step
    def __str__(self):
        if not self.end:
            return f"range({self.start})"
        elif not self.step:
            return f"range({self.start},{self.end})"
        else:
            return f"range({self.start},{self.end},{self.step})"

    def __eq__(self, other):
        return isinstance(other, Range) and self.start == other.start and self.end == other.end and self.step == other.step
    
    def get_value(self, context):
        start = self.start(context) if isinstance(self.start, Expression) else self.start
        if not self.end:
            return range(start)
        end = self.end(context) if isinstance(self.end, Expression) else self.end
        if not self.step:
            return range(start, end)
        step = self.step(context) if isinstance(self.step, Expression) else self.step
        return range(start, end, step)
    
    def set_value(self, context, value):
        raise ValueError("Cannot set value to a range object")
    
class Listing(Primitive):
    def __init__(self, items:List[Object]):
        self.items = items

    def __str__(self):
        return f"{self.items}"
    
    def __eq__(self, other):
        return isinstance(other, Listing) and self.items == other.items

    def get_value(self, context):
        return [i.get_value(context) for i in self.items]
    
    def set_value(self, context, value: list):
        for i, v in enumerate(value):
            self.items[i].set_value(context, v)

class Dictionary(Primitive):
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

    def __init__(self, name:Expression):
        self._name = name

    @staticmethod
    def createNamedObject(db:str, name:Expression):
        switcher = {
            "&reg": Register,
            "&sym": SymbolicValue,
            "&io": Stream,
            "&vars": VariableRef
        }
        return switcher.get(db,None)(name)
        
        
class Stream(ReferenceObject):
    def __init__(self, stream:Expression):
        super().__init__(stream)
    @property
    def stream(self):
        return self._name
    
    def __str__(self):
        return f"&io.{self.stream}"
    def get_value(self, context):
        return self.debugger(context).get_stream(self.stream(context))
    def set_value(self, context, value):
        raise ValueError("Cannot set value to a stream object")
    def __eq__(self, other):
        return isinstance(other, Stream) and self.stream == other.stream

class SymbolicValue(ReferenceObject):
    def __init__(self, name):
        super().__init__(name)

    def get_value(self, context):
        #get variable value and 
        return self.debugger(context).get_symbol(self._name(context))
    
    def set_value(self, context, value):
        assert isinstance(value,AngrValueType)
        self.debugger(context).set_symbol(self._name(context), value)

    def __str__(self):
        return f"&sym.{self._name}"
    def __eq__(self, other):
        return isinstance(other, SymbolicValue) and self._name == other._name
    
class Memory(ReferenceObject):
    def __init__(self, address:Expression, size:Expression|None):
        super().__init__(Literal(f"{address}->{size}"))
        self.address = address
        self.size = size 

    def get_value(self, context):
        return self.debugger(context).get_memory(self.address(context), self.size(context) if self.size else 0)

    def set_value(self, context, value):
        assert isinstance(value,AngrValueType)
        self.debugger(context).set_memory(self.address(context), value, self.size(context) if self.size else None)
    
    def __str__(self):
        if isinstance(self.address, Literal):
            return f"&mem[{hex(self.address.value)}->{self.size}]"
        else:
            return f"&mem[{self.address}->{self.size}]"
    def __eq__(self, other):
        return isinstance(other, Memory) and self.address == other.address and self.size == other.size
    
class Register(ReferenceObject):
    def __init__(self, name):
        self.name = name

    @property
    def register(self):
        return self.name
    def get_value(self, context):
        return self.debugger(context).get_register(self.register(context))
    
    def set_value(self, context, value):
        if isinstance(value, int) or isinstance(value, claripy.ast.BV):
            self.debugger(context).set_register(self.register(context), value)
        else:
            raise ValueError(f"Invalid value type: {value}")    
    def __str__(self):
        return f"&reg.{self.register}"
    def __eq__(self, other):
        return isinstance(other, Register) and self.register == other.register
    
class StateObject(ReferenceObject):
    def __init__(self):
        super().__init__(Literal("state"))
    def get_value(self, context):
        return self.debugger(context).current_state
    def set_value(self, context, value):
        raise ValueError("Cannot set value to a state object")
    def __str__(self):
        return f"&state"
    def __eq__(self, other):
        return isinstance(other, StateObject)
class Negate(Expression):
    def __init__(self, expr:Expression):
        self.expr = expr

    def __call__(self, context:ExecutionContext):
        return -self.expr(context)
    
    def __str__(self):
        return f"-{self.expr}"
    
    def __eq__(self, other):
        return isinstance(other, Negate) and self.expr == other.expr
    
class VariableRef(ReferenceObject):
    def __init__(self, name:Expression, is_static=False):
        self.name:Expression = name
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
    
    def var_exists(self, context):
        return self.name(context) in context.variables

    
    def get_value(self, context):
        if self.var_exists(context):
            return context[self.name(context)].value
        sym = self.debugger(context).find_symbol(self.name(context))
        if not sym is None:
            return sym
        raise KeyError(f"Unknown variable: {self.name}")
        
    def set_value(self, context, value):
        context[self.name(context)] = value

class Property(ReferenceObject):
    def __init__(self, obj:Object, prop:str):
        super().__init__(Literal(f"{obj}.{prop}"))
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
        o = None
        if isinstance(self.obj, VariableRef) and not self.obj.var_exists(context):
            if e := context.find_enum(self.obj.name(context)):
                o = e
            else:
                raise InvalidArgumentError(f"Unknown variable: {self.obj}")
        else:
            o = self.obj.get_value(context)
        if hasattr(o, self.prop):
            return getattr(o, self.prop)
        else:
            raise InvalidArgumentError(f"Object {o} does not have property {self.prop}")
        
class IndexedProperty(Property):
    def __init__(self, obj:Object, index:Expression):
        super().__init__(obj, f"{index}")
        self.index = index
    
    def __str__(self):
        return f"{self.obj}[{self.index}]"
    
    def set_value(self, context, value: Any):
        o = self.obj.get_value(context)
        if is_indexable(o):
            index = self.index(context)
            o[index] = value
        else:
            raise InvalidArgumentError(f"Object {o} does not support indexing")
    def get_value(self, context):
        o = self.obj.get_value(context)
        index = self.index(context)
        if is_indexable(o):
            return o[index]
        else:
            raise InvalidArgumentError(f"Object {o} does not support indexing")

class Slice(Property):
    def __init__(self, obj:Object, start:int|Expression, end:int|Expression):
        super().__init__(obj, f"{start}:{end}")
        self.start = start
        self.end = end
    
    def get_value(self, context):
        start = self.start(context) if isinstance(self.start, Expression) else self.start
        end = self.end(context) if isinstance(self.end, Expression) else self.end
        if start == -1:
            if end == -1:
                return self.obj.get_value(context)
            else:
                return self.obj.get_value(context)[:end]
        else:
            if end == -1:
                return self.obj.get_value(context)[start:]
            else:
                return self.obj.get_value(context)[start:end]
    
    def set_value(self, context, value: list):
        o = self.obj.get_value(context)
        if isinstance(value, list):
            start = self.start(context) if isinstance(self.start, Expression) else self.start
            end = self.end(context) if isinstance(self.end, Expression) else self.end
            o[start:end] = value
        else:
            raise InvalidArgumentError(f"Object {o} does not support slicing")
    def __repr__(self):
        return f"{self.obj}[{self.start}:{self.end}]"
    def __eq__(self, other):
        return isinstance(other, Slice) and self.start == other.start and self.end == other.end
    
class Inclusion(Expression):
    def __init__(self, obj:Object, item:Object):
        self.obj = obj
        self.item = item
    
    def __call__(self, context: ExecutionContext):
        o = self.obj.get_value(context)
        i = self.item.get_value(context)
        return o in i
    
    def __str__(self):
        return f"{self.item} in {self.obj}"
    
    def __eq__(self, other):
        return isinstance(other, Inclusion) and self.obj == other.obj and self.item == other.item
    
class Comparison(Expression):
    def __init__(self, left:Expression, operator:Operator, right:Expression):
        self.left = left
        self.operator:Operator = operator
        self.right = right
        self.init = False


    def reorder_comparison(self,comp):
        # Base case: If it's not a Comparison, return it as is
        if not isinstance(comp, Comparison):
            return comp
        
        # Recursively reorder left and right comparisons first
        left = self.reorder_comparison(comp.left)
        right = self.reorder_comparison(comp.right)

        # If the right is a Comparison and has higher precedence than current,
        # restructure to respect precedence
        if isinstance(right, Comparison) and right.operator.precedence < comp.operator.precedence: 
            # Re-arrange: the right side will become a new left-side comparison
            new_left = Comparison(left, comp.operator, right.left)
            return Comparison(new_left, right.operator, right.right)
        
        # Otherwise, just return the current comparison
        return Comparison(left, comp.operator, right)

    def __call__(self, context:ExecutionContext):
        # handle operator precedence, the right side of the expression may be a comparison
        if not self.init:
            self = self.reorder_comparison(self)
            self.init = True

        left = self.left(context)
        right = self.right(context)
        switch = {
            Operator.AND: claripy.And,
            Operator.OR: claripy.Or,
        }
        if self.operator == Operator.ADD and isinstance(left, claripy.ast.BV) and isinstance(right, claripy.ast.BV):
            return claripy.Concat(left, right)
        elif isinstance(left, claripy.ast.Base) or isinstance(right, claripy.ast.Base):
            op = switch.get(self.operator, None)
            if op:
                v= op(left, right)
                if v == NotImplemented:
                    raise ValueError(f"Invalid operator {self.operator} for {type(left)} and {type(right)}")
                return v
        operation = Operator.convert_to_magic_method(self.operator)
        if operation is None:
            raise ValueError(f"Invalid operator {self.operator}")
        v = getattr(type(left), operation)(left, right)
        if v == NotImplemented:
            v = getattr(type(right), operation)(left, right)
            if v == NotImplemented:
                raise ValueError(f"Invalid operator {self.operator} for {type(left)} and {type(right)}")
        return v
    
    def __str__(self):
        return f"{self.left} {self.operator} {self.right}"
    
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Comparison) and self.left == value.left and self.operator == value.operator and self.right == value.right
    
class Constraint(Expression):
    pass
class IfConstraint(Constraint):
    def __init__(self, condition:Expression, true_constraint:Constraint, false_constraint:Constraint):
        self.condition = condition
        self.true_constraint = true_constraint
        self.false_constraint = false_constraint

    def __call__(self, context:ExecutionContext):
        cthen =  self.true_constraint(context)
        if not isinstance(cthen, claripy.ast.Base):
            cthen = self.debugger(context).render_argument(cthen,False)
        celse = self.false_constraint(context)
        if not isinstance(celse, claripy.ast.Base):
            celse = self.debugger(context).render_argument(celse,False)
        return claripy.If(self.condition(context), cthen, celse)
    
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
    def __call__(self, context):
        raise NotImplementedError
    
class BASECommand(Command):
    def __init__(self, base:str):
        self.base = base

    def __call__(self, context:ExecutionContext):
        raise NotImplementedError
    
    def __str__(self):
        return f"{self.base}"
    def __eq__(self, other):
        return isinstance(other, BASECommand) and self.base == other.base

BREAK = BASECommand('break')
CONTINUE = BASECommand('continue')

def to_val(arg, context:ExecutionContext):
    v = arg(context)
    if isinstance(arg, ReferenceObject):
        if isinstance(v, str) or isinstance(v, bytes):
            return repr(v)
    if isinstance(v, claripy.ast.Base):
        from dAngr.cli.command_line_debugger import dAngrExecutionContext
        dbg = cast(dAngrExecutionContext, context.root).debugger
        v = dbg.eval_symbol(v, DataType.bytes, endness =dbg.project.arch.memory_endness) # type: ignore
        return repr(dbg.cast_to(v, DataType.str))
    return v

class PythonCommand(Command):
    def __init__(self, *cmds:Expression|str|int|bytes, **kwargs:Expression):
        cc = [ Literal(c) if isinstance(c, (str,int,bytes)) else c for c in cmds if isinstance(c, (Expression,str,int,bytes))]
        self.cmds:List[Expression] = self._merge_consecutive_literals(cc)
        self.kwargs:Dict[str,Expression] = kwargs

    
    def __call__(self, context:ExecutionContext):
        # copy the commands locally
        # execute the commands if it is an Expression and replace the entry in the copy with the result
        c = context.clone()
        results = [to_val(a,c) for a in self.cmds] + [f"{k}={to_val(v,c)}" for k,v in self.kwargs.items()]
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                cmd = "".join([str(r) for r in results])
                vars = context.python_context.get("global",{})
                glo = context.python_context.get("local", {})
                # split the last line, execute the first lines, and eval the last line
                if "\n" in cmd:
                    lines,line = cmd.rsplit("\n",1)
                else:
                    lines, line = "", cmd
                
                exec(lines,glo,vars)
                try:
                    context.return_value = eval(line,glo,vars)
                except SyntaxError:
                    exec(line,glo,vars)
                context.python_context = {"global":glo, "local":vars}
            except Exception as e:
                raise CommandError(f"Error executing python command: {cmd} ({e})")
        if stdout := stdout_buffer.getvalue():
            self.debugger(context).conn.send_output(stdout)
        if stderr := stderr_buffer.getvalue():
            self.debugger(context).conn.send_error(stderr)
        return context.return_value
    
    def __str__(self):
        return "".join([ str(c) for c in self.cmds])
    def __eq__(self, other):
        return isinstance(other, PythonCommand) and self.cmds == other.cmds
    
class BashCommand(Command):
    def __init__(self, *cmds:Expression|str|int|bytes):
        cc = [ Literal(c) if isinstance(c, (str,int,bytes)) else c for c in cmds if isinstance(c, (Expression,str,int,bytes))]
        self.cmds:List[Expression] = self._merge_consecutive_literals(cc)

    def __call__(self, context):
        c = context.clone()
        args = "".join([str(a(c)) for a in self.cmds]).split(" ")
        context.return_value = subprocess.run(args, capture_output=True, text=True).stdout.strip()
        return context.return_value
    
    def __str__(self):
        return "".join([ str(c) for c in self.cmds])
    def __eq__(self, other):
        return isinstance(other, BashCommand) and self.cmds == other.cmds
         
class DangrCommand(Command):
    def __init__(self, cmd:str, package:str|None, *args:Expression, **kwargs:Expression):
        self.cmd = cmd
        self.package = package
        self.args:List[Expression] = [*args]
        self.kwargs:Dict[str,Expression] = kwargs

    def _get_enum_value(self, name, spec):
        if get_origin(spec.dtype) is UnionType:
            types = get_args(spec.dtype)
        else:
            types = [spec.dtype]

        if Enum in types:
            for t in types:
                if issubclass(t, Enum):
                    if name in t.__members__: # type: ignore
                        return t[name] # type: ignore
        return None
    def _accept_string(self, name, spec):
        if get_origin(spec.dtype) is UnionType:
            types = get_args(spec.dtype)
        else:
            types = [spec.dtype]
        if str in types:
            return name
        return None

    def _check_arg(self, arg, context:ExecutionContext, spec):

        #TODO, what if  dtype is a tuple
        # if spec.dtype == str and isinstance(arg, VariableRef):
        #     return arg.name
        if isinstance(spec.dtype, type) and issubclass(spec.dtype, ReferenceObject):
            return arg
        elif isinstance(spec.dtype, type) and issubclass(spec.dtype, Enum):
            return spec.dtype[arg.name(context)]
        else:
            if isinstance(arg, VariableRef):
                if arg.var_exists(context):
                    return arg(context)
                name = arg.name(context)
                if e:= self._get_enum_value(name, spec):
                    return e
                if s:= self._accept_string(name, spec):
                    return s
                raise DebuggerCommandError(f"Unknown variable: {arg.name}")
        return arg(context) 

        

    def __call__(self, context:ExecutionContext):
        from dAngr.cli.command_line_debugger import BuiltinFunctionDefinition
        spec = None
        spec = context.find_function(self.package, self.cmd)
        if not spec:
            if self.package:
                raise CommandError(f"Unknown command: {self.package}.{self.cmd}")
            if context.find_variable(self.cmd):
                return context[self.cmd].value
            elif e:= context.find_enum(self.cmd):
                return e
            else:
                raise CommandError(f"Unknown command: {self.cmd}")
        # spec = cast(BuiltinFunctionDefinition, spec)
        #handle function arguments
        s_args = spec.args

        if len(spec.args) < len(self.args):
            #handle variable arguments
            if spec.args and  spec.args[-1].dtype == tuple:
                # copy the last argument until there are enough arguments
                while len(s_args) < len(self.args):
                    s_args.append(s_args[-1])
            else:
                raise CommandError(f"Too many arguments. Expected {len(spec.args)} but got {len(self.args)}")
        # check arg type and if the arguments match the function signature
        arguments = [ self._check_arg(arg, context, s_args[i]) for i,arg in enumerate(self.args) ]
        named_args = {k: self._check_arg(v,context, spec.get_arg_by_name(k)) for k,v in self.kwargs.items()}
        if isinstance(spec, BuiltinFunctionDefinition):
            # check if the function signature matches
            check_signature_matches(spec.func, spec, arguments, named_args)

        log.debug(lambda:f"Calling {self.cmd} with {arguments} {named_args}")

        # call the function
        context.return_value = spec(context, *arguments, **named_args)
        return context.return_value

            

    def __str__(self):
        return f"{self.cmd} {[str(a) for a in self.args]} {self.kwargs}"
    def __eq__(self, other):
        return isinstance(other, DangrCommand) and self.cmd == other.cmd and self.package == other.package and self.args == other.args and self.kwargs == other.kwargs

    