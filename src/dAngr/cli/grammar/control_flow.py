
from textwrap import indent
from typing import List

from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.cli.grammar.expressions import Expression, Iterable, VariableRef
from .statements import Statement
from .script import Body

class ControlFlow(Statement):
    def __init__(self, body: Body):
        self.body: Body = body
    pass

class IfThenElse(ControlFlow):
    def __init__(self, condition: Expression, if_body: Body, else_body: Body|None = None):
        super().__init__(if_body)
        self.condition = condition
        self.else_body: Body = else_body if else_body else Body([])

    async def __call__(self, context: ExecutionContext):
        if Expression.toBool(self.condition(context)):
            return await self.body(ExecutionContext(context))
        elif self.else_body.statements:
            return await self.else_body(ExecutionContext(context))
        return

    def __repr__(self):
        return f"if {self.condition}:\n{indent(str(self.body), '   ')}\nelse:\n{indent(str(self.else_body), '   ')}"

    def __eq__(self, value: object) -> bool:
        return isinstance(value, IfThenElse) and self.condition == value.condition and self.body == value.body and self.else_body == value.else_body

class WhileLoop(ControlFlow):
    def __init__(self, condition: Expression, body: Body):
        super().__init__(body)
        self.condition = condition

    async def __call__(self, context: ExecutionContext):
        while self.condition(context):
            await self.body(ExecutionContext(context))

    def __repr__(self):
        return f"while {self.condition}:\n{indent(str(self.body), '   ')}"

    def __eq__(self, value: object) -> bool:
        return isinstance(value, WhileLoop) and self.condition == value.condition and self.body == value.body

class ForLoop(ControlFlow):
    def __init__(self, iterable: Iterable, body: Body, item: VariableRef, index:VariableRef|None= None):
        super().__init__(body)
        self.index = index
        self.item = item
        self.iterable = iterable

    async def __call__(self, context: ExecutionContext):
        if self.index:
            for index, item in self.iterable:
                ctx = ExecutionContext(context)
                ctx[self.index] = index
                ctx[self.item] = item
                await self.body(ctx)
        else:
            for item in self.iterable:
                ctx = ExecutionContext(context)
                ctx[self.item] = item
                await self.body(ctx)

    def __repr__(self):
        if self.index:
            return f"for {self.index},{self.item} in {self.iterable}:\n{indent(str(self.body), '   ')}"
        else:
            return f"for {self.item} in {self.iterable}:\n{indent(str(self.body), '   ')}"

    def __eq__(self, value: object) -> bool:
        return isinstance(value, ForLoop) and self.index == value.index and self.item == value.item and self.iterable == value.iterable and self.body == value.body