
from claripy import List

from dAngr.cli.grammar.definitions import Definition
from dAngr.cli.grammar.execution_context import ExecutionContext



class Body:
    def __init__(self, statements):
        from dAngr.cli.grammar.statements import Statement
        self.statements:List[Statement] = statements
        
    async def __call__(self, context:ExecutionContext):
        result = None
        for s in self.statements:
            result = await s(context)
        return result

    def __repr__(self):
        return "\n".join([str(s) for s in self.statements])
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Body) and self.statements == value.statements

class Script(Body):
    def __init__(self, statements, definitions):
        super().__init__(statements)
        self.definitions:List[Definition] = definitions

    async def __call__(self, context:ExecutionContext):
        for d in self.definitions:
            context.addDefinition(d.name, d) # type: ignore
        result = None
        for s in self.statements:
            result = await s(context)
        for d in self.definitions:
            context.removeDefinition(d.name)
        return result

    def __repr__(self):
        return f"Script({self.statements})"
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Script) and self.statements == value.statements and self.definitions == value.definitions
