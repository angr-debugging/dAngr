
from textwrap import indent
from typing import List

from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.cli.grammar.expressions import BREAK, BASECommand, Expression, Range, VariableRef
from dAngr.utils.utils import is_iterable
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

    def __call__(self, context: ExecutionContext):
        if Expression.toBool(self.condition(context)):
            return self.body(ExecutionContext(context))
        elif self.else_body.statements:
            return self.else_body(ExecutionContext(context))
        return None

    def __repr__(self):
        return f"if {self.condition}:\n{indent(str(self.body), '   ')}\nelse:\n{indent(str(self.else_body), '   ')}"

    def __eq__(self, value: object) -> bool:
        return isinstance(value, IfThenElse) and self.condition == value.condition and self.body == value.body and self.else_body == value.else_body

class WhileLoop(ControlFlow):
    def __init__(self, condition: Expression, body: Body):
        super().__init__(body)
        self.condition = condition

    def __call__(self, context: ExecutionContext):
        while self.condition(context):
            r = self.body(ExecutionContext(context))
            if r == BREAK:
                break
            if isinstance(r, BASECommand) and r.base == "return":
                return r(context)

    def __repr__(self):
        return f"while {self.condition}:\n{indent(str(self.body), '   ')}"

    def __eq__(self, value: object) -> bool:
        return isinstance(value, WhileLoop) and self.condition == value.condition and self.body == value.body

class ForLoop(ControlFlow):
    def __init__(self, iterable: Expression, body: Body, item: VariableRef, index:VariableRef|None= None):
        super().__init__(body)
        self.index = index
        self.item = item
        self.iterable:Expression = iterable

    def __call__(self, context: ExecutionContext):
        if isinstance(self.iterable, Expression):
            iterable = self.iterable(context)
            #check if iterable is iterable
            if not is_iterable(iterable):
                raise ValueError(f"{iterable} is not iterable")
        else:
            iterable = self.iterable
        if self.index:
            for index, item in enumerate(iterable): # type: ignore
                ctx = ExecutionContext(context)
                ctx[self.index.name(context)] = index
                ctx[self.item.name(context)] = item
                r = self.body(ctx)
                if r == BREAK:
                    break
                if isinstance(r, BASECommand) and r.base == "return":
                    return r(context)
        else:
            for item in iterable: # type: ignore
                ctx = ExecutionContext(context)
                ctx[self.item.name(context)] = item
                r = self.body(ctx)
                if r == BREAK:
                    break
                if isinstance(r, BASECommand) and r.base == "return":
                    return r(context)

    def __repr__(self):
        if self.index:
            return f"for {self.index},{self.item} in {self.iterable}:\n{indent(str(self.body), '   ')}"
        else:
            return f"for {self.item} in {self.iterable}:\n{indent(str(self.body), '   ')}"

    def __eq__(self, value: object) -> bool:
        return isinstance(value, ForLoop) and self.index == value.index and self.item == value.item and self.iterable == value.iterable and self.body == value.body