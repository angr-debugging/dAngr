
from claripy import List

from dAngr.cli.grammar.definitions import Definition, FunctionContext
from dAngr.cli.grammar.execution_context import ExecutionContext
from dAngr.cli.grammar.expressions import VariableRef
from dAngr.cli.grammar.statements import Assignment, Statement



class Body:
    def __init__(self, statements):
        from dAngr.cli.grammar.statements import Statement
        self.statements:List[Statement] = statements

    def is_static(self, statement):
        from dAngr.cli.grammar.statements import Assignment
        if isinstance(statement, Assignment) and isinstance(statement.variable, VariableRef):
            return statement.variable.is_static
        elif isinstance(statement, VariableRef):
            return statement.is_static
        return False

        
    async def __call__(self, ctx:ExecutionContext):
        result = None
        if isinstance(ctx, FunctionContext):
            func_name = ctx.function.name
        else:
            func_name = "main"
        context = ExecutionContext(parent=ctx)
        for s in self.statements:
            if self.is_static(s):
                await self._prepare_static(context, func_name, s)
            result = await s(context)
        self._repair_static(context, func_name)
        return result
    async def _prepare_static(self, context:ExecutionContext, func_name:str, s:Statement):
        var_name = None
        if isinstance(s, Assignment) and isinstance(s.variable, VariableRef):
            var_name = s.variable.name
        elif isinstance(s, VariableRef):
            var_name = s.name
        else:
            raise Exception("Unknown statement type")
        if context.root["static_" + func_name +"_"+ var_name] is None:
            if isinstance(s, Assignment):
                context.root["static_"+ func_name +"_"+ var_name] = await s.value(context)
            else:
                context.root["static_"+ func_name +"_"+ var_name] = None
        context[var_name] = context.root["static_"+ func_name +"_"+ var_name]
    def _repair_static(self, context:ExecutionContext, func_name:str):
        #for all statements that are static, copy the value from context to the root context
        for s in self.statements:
            if self.is_static(s):
                var_name = None
                if isinstance(s, Assignment) and isinstance(s.variable, VariableRef):
                    var_name = s.variable.name
                elif isinstance(s, VariableRef):
                    var_name = s.name
                else:
                    raise Exception("Unknown statement type")
                context.root["static_"+ func_name +"_"+ var_name] = context[var_name]

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
            context.add_definition(d.name, d) # type: ignore
        result = None
        for s in self.statements:
            result = await s(context)
        return result

    def __repr__(self):
        return f"Script({self.statements})"
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Script) and self.statements == value.statements and self.definitions == value.definitions
