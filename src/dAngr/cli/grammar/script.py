
from dAngr.angr_ext.definitions import Definition, FunctionContext
from dAngr.angr_ext.execution_context import ExecutionContext
from dAngr.angr_ext.expressions import BREAK, CONTINUE, BASECommand, VariableRef
from dAngr.cli.grammar.statements import Assignment, Statement
from typing import List

class StatementException(Exception):
    pass

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

        
    def __call__(self, ctx:ExecutionContext):
        result = None
        if isinstance(ctx, FunctionContext):
            func_name = ctx.function.name
        else:
            func_name = "main"
        context = ExecutionContext(parent=ctx)
        try:
            statement_cnt = 0
            for s in self.statements:
                try:
                    if isinstance(s,BASECommand):
                        if s == BREAK:
                            return s
                        elif s == CONTINUE:
                            return
                        elif s.base == "return":
                            return s(context)
                    if self.is_static(s):
                        self._prepare_static(context, func_name, s)
                    result = s(context)
                    if result == BREAK:
                        return result
                    if isinstance(result, BASECommand) and result.base == "return":
                        return result(context)
                    statement_cnt += 1
                except StatementException as e:
                    raise e
                except Exception as e:
                    raise StatementException(f"Error executing statement {s} in function {func_name} line:{statement_cnt}\n\t{e}")
        finally:
            self._repair_static(context, func_name)
        return result
    
    def _prepare_static(self, context:ExecutionContext, func_name:str, s:Statement):
        var = None
        if isinstance(s, Assignment) and isinstance(s.variable, VariableRef):
            var = s.variable
        elif isinstance(s, VariableRef):
            var= s
        else:
            raise Exception("Unknown statement type")
        stat_name = var.static_name
        if context.root.find_variable(stat_name) is None:
            context.root.add_variable(stat_name, None)
        if isinstance(s, Assignment): #set global variable on each execution
            val = s.value(context)
            context.root[stat_name].value = val
        context.add_variable(var.name(context), context.root[stat_name].value)

    def _repair_static(self, context:ExecutionContext, func_name:str):
        #for all statements that are static, copy the value from context to the root context
        for s in self.statements:
            if self.is_static(s):
                var = None
                if isinstance(s, Assignment) and isinstance(s.variable, VariableRef):
                    var = s.variable
                elif isinstance(s, VariableRef):
                    var = s
                else:
                    raise Exception("Unknown statement type")
                context.root[var.static_name] = context[var.name].value

    def __repr__(self):
        return "\n".join([str(s) for s in self.statements])
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Body) and self.statements == value.statements

class Script(Body):
    def __init__(self, statements, definitions):
        super().__init__(statements)
        self.definitions:List[Definition] = definitions

    def __call__(self, context:ExecutionContext):
        for d in self.definitions:
            context.add_definition(d.name, d) # type: ignore
        result = None
        for s in self.statements:
            result = s(context)
        return result

    def __repr__(self):
        return f"Script({self.statements})"
    def __eq__(self, value: object) -> bool:
        return isinstance(value, Script) and self.statements == value.statements and self.definitions == value.definitions
