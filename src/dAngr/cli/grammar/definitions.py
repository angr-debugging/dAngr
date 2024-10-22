
from textwrap import indent
from typing import Any
from claripy import List
from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.cli.grammar.expressions import VariableRef
from dAngr.exceptions import InvalidArgumentError
from dAngr.utils import undefined

class Definition:
    def __init__(self, name):
        self.name = name
    async def __call__(self, context:ExecutionContext, *args: Any, **kwds: Any) -> Any:
        raise NotImplementedError
    def __repr__(self):
        return f"def {self.name}"
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Definition) and self.name == value.name

class ArgumentSpec:
    def __init__(self, name:str,  dtype:type = type[Any], default=undefined, description:str="") -> None:
        self._name = name
        self._default = default
        self._dtype = dtype
        self._description = description
    @property
    def name(self):
        return self._name
    @property
    def isOptional(self):
        return self._default is not None
    @property
    def default(self):
        return self._default
    @property
    def dtype(self):
        return self._dtype
    @property
    def description(self):
        return self._description
    def __repr__(self):
        r = self.name
        if self.dtype != type[Any]:
            if isinstance(self.dtype, object):
                r += f":{self.dtype.__name__}"
            else:
                r += f":{self.dtype}"
        if self.default != undefined:
            r += f"={self.default}"
        if self.description:
            r += f" {self.description}"
        return r

    def __eq__(self, value: object) -> bool:
        return isinstance(value, ArgumentSpec) and self.name == value.name and self.dtype == value.dtype and self.default == value.default and self.description == value.description

#Definitions    
class FunctionDefinition(Definition):
    def __init__(self, name, package:str|None, args:List[ArgumentSpec]):
        self._name = name
        self._package = package if package else ""
        self._args:List[ArgumentSpec] = args
    @property
    def name(self):
        return self._name
    @property
    def package(self):
        return self._package
    @property
    def args(self):
        return self._args
    @property
    def required_arguments(self) -> List[ArgumentSpec]:
        return [a for a in self._args if a.default == undefined]
    @property
    def optional_arguments(self) -> List[ArgumentSpec]:
        return [a for a in self._args if a.default != undefined]
    
    def get_arg_by_name(self, name:str) -> ArgumentSpec:
        for arg in self._args:
            if arg.name == name:
                return arg
        if n:= next((arg for arg in self._args if arg.name == 'kwargs'), None):
            return arg
        
        raise InvalidArgumentError(f"Unknown argument {name}")
    def __repr__(self):
        return f"def {self.name}({",".join([str(a) for a in self.args])})"
    
    def __eq__(self, value: object) -> bool:
        return isinstance(value, FunctionDefinition) and self.name == value.name and self.args == value.args

#declaration
class Body:
    async def __call__(self, context):
        raise NotImplementedError
    
class FunctionContext(ExecutionContext):
    def __init__(self, function:FunctionDefinition, parent=None):
        super().__init__(parent)
        self.function = function
    
class CustomFunctionDefinition(FunctionDefinition):
    def __init__(self, name, args:List[ArgumentSpec], body):
        super().__init__(name, None, args)
        self.body:Body = body


    async def __call__(self, context, *arg_values, **named_args):
        # add args
        context = FunctionContext(self, context)
        # match arg_values with required and optional args
        for i, arg in enumerate(arg_values):
            context[self.args[i].name]= arg_values[i]
        for k,v in named_args.items():
            context[k] = v
            
        result = await self.body(context)
        # remove args
        for arg in self.args:
            if isinstance(arg, VariableRef):
                del context.variables[arg.name]
        return result

    def __repr__(self):
        f = super().__repr__()
        return f"{f}\n{indent(str(self.body),"   ")}"
    
    def __eq__(self, value: object) -> bool:
        return isinstance(value, CustomFunctionDefinition) and self.name == value.name and self.args == value.args and self.body == value.body