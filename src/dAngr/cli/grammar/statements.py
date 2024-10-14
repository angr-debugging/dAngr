
from abc import abstractmethod
from textwrap import indent

from claripy import List

from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.cli.grammar.expressions import ReferenceObject

#Statements
class Statement:
    @abstractmethod
    async def __call__(self, context):
        raise NotImplementedError
    
    @staticmethod
    def flatten(lst:List['Statement']):
        newList =[]
        for item in lst:
            if isinstance(item, list):
                newList.extend(item)
            else:
                newList.append(item)
        return newList
    @abstractmethod
    def __repr__(self):
        raise NotImplementedError
    @abstractmethod
    def __eq__(self, value: object) -> bool:
        raise NotImplementedError


class Assignment(Statement):
    def __init__(self, variable:ReferenceObject, value):
        self.variable:ReferenceObject = variable
        self.value = value

    async def __call__(self, context:ExecutionContext):
        value = await self.value(context)
        self.variable.set_value(context, value)
        return None

    def __repr__(self):
        return f"{self.variable} = {self.value}"
    
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Assignment) and self.variable == value.variable and self.value == value.value
    
