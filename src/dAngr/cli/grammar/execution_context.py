
from typing import Any, Dict

from dAngr.utils import Variable

from dAngr.exceptions import KeyError

        
    
class ExecutionContext:
    def __init__(self, parent=None):
        from .definitions import Definition
        self._variables: Dict[str,Variable] = {}
        self._definitions:Dict[str,Definition] = {}
        self._parent:ExecutionContext|None= parent # type: ignore
        self.return_value = None

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
    
    def __setitem__(self, name, value):
        if name in self._variables:
            self._variables[name]._value = value
        elif self._parent and name in self._parent.variables:
            self._parent[name].value = value
        else:
            self._variables[name] = Variable(name,value)
    def addVariable(self, name:str, value:Any):
        self._variables[name] = Variable(name, value)
    def removeVariable(self, name:str):
        if name in self._variables:
            del self._variables[name]
    def addDefinition(self, name:str, value):
        self._definitions[name] = value # type: ignore
    def removeDefinition(self, name:str):
        if name in self._definitions:
            del self._definitions[name]
    @property
    def definitions(self):
        # merge dict from the parent with precedence to the current context
        return {**self._parent.definitions, **self._definitions} if self._parent else self._definitions
    @property
    def functions(self):
        from .definitions import FunctionDefinition
        return {k:v for k,v in self.definitions.items() if isinstance(v, FunctionDefinition)}
    @property
    def variables(self)->Dict[str,Variable]:
        # merge dict from the parent with precedence to the current context
        return {**self._parent.variables, **self._variables} if self._parent else self._variables
