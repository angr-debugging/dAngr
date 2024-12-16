
from typing import Any, Dict

import angr

from dAngr.utils import Variable

from dAngr.exceptions import KeyError

        
    
class ExecutionContext:
    def __init__(self, parent=None):
        from .definitions import Definition
        self._variables: Dict[str,Variable] = {}
        self._definitions:Dict[str,Definition] = {}
        self._parent:ExecutionContext|None= parent # type: ignore
        self.enums = {"options":angr.options}
        self.python_context = {}
        self.return_value = None
        
    @property
    def root(self):
        return self._parent.root if self._parent else self
    
    def clone(self):
        e = ExecutionContext() # type: ignore
        e._variables = self._variables.copy()
        e._definitions = self._definitions.copy()
        e._parent = self
        return e
    
    def __getitem__(self, name) -> Variable:
        if name in self._variables:
            return self._variables[name]
        if self._parent and name in self._parent.variables:
            return self._parent[name]
        raise KeyError(f"Unknown variable: {name}")
    
    def find_variable(self, name:str):
        if name in self._variables:
            return self._variables[name]
        if self._parent and name in self._parent.variables:
            return self._parent[name]
        if "@"+name in self.root.variables:
            return self.root.variables["@"+name]
        return None
    
    def find_enum(self, name:str):
        if name in self.enums:
            return self.enums[name]
        if self._parent:
            return self._parent.find_enum(name)
        return None
    
    
    def __setitem__(self, name:str, value):
        assert not isinstance(value, Variable)
        if name in self._variables:
            self._variables[name]._value = value
        # Check if itself function context is
        elif self._parent and name in self._parent.variables:
            self._parent[name].value = value
        else:
            self.add_variable(name, value)

    def add_variable(self, name:str, value:Any):
        assert not isinstance(value, Variable)
        self._variables[name] = Variable(name, value)

    def remove_variable(self, name:str):
        if name in self._variables:
            del self._variables[name]
    def add_definition(self, name:str, value):
        self._definitions[name] = value # type: ignore
    def remove_definition(self, name:str):
        if name in self._definitions:
            del self._definitions[name]

    def get_definition(self, name:str):
        if definition := self.find_definition(name):
            return definition
        raise KeyError(f"Unknown definition: {name}")
    def find_definition(self, name:str):
        if name in self._definitions:
            return self._definitions[name]
        if self._parent and name in self._parent.definitions:
            return self._parent.get_definition(name)
        return None
    @property
    def definitions(self):
        # merge dict from the parent with precedence to the current context
        return {**self._parent.definitions, **self._definitions} if self._parent else self._definitions
    @property
    def functions(self):
        from .definitions import FunctionDefinition
        return {k:v for k,v in self.definitions.items() if isinstance(v, FunctionDefinition)}
    
    def find_function(self, package:str|None, name:str):
        from dAngr.cli.command_line_debugger import BuiltinFunctionDefinition
        if f:= next((f for f in self.functions.values() if (f.name == name ) and (f.package == package if package else True)), None):
            return f
        else:
            return next((f for f in self.functions.values() if isinstance(f, BuiltinFunctionDefinition) and (f.short_name == name ) and not package), None)
    
    @property
    def variables(self)->Dict[str,Variable]:
        # merge dict from the parent with precedence to the current context
        return {**self._parent.variables, **self._variables} if self._parent else self._variables
