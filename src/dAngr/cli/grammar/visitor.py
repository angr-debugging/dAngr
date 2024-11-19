

from antlr4 import TerminalNode
from dAngr.exceptions import ParseError
from dAngr.cli.grammar.antlr.dAngrParser import dAngrParser
from dAngr.cli.grammar.antlr.dAngrVisitor import dAngrVisitor
from dAngr.cli.grammar.statements import Assignment,  Statement
from dAngr.cli.grammar.control_flow import IfThenElse, WhileLoop, ForLoop
from dAngr.cli.grammar.script import Script, Body
from dAngr.cli.grammar.definitions import ArgumentSpec, CustomFunctionDefinition
from dAngr.cli.grammar.expressions import BREAK, CONTINUE, DangrCommand, Dictionary, IfConstraint, Inclusion, Listing, Memory, Negate, Operator, PythonCommand, BashCommand, Comparison, Literal, Property, IndexedProperty, Range, ReferenceObject, Slice, StateObject, VariableRef
from dAngr.utils.utils import parse_binary_string


class dAngrVisitor_(dAngrVisitor):
    def __init__(self):
        self.operators = {
            "**": Operator.POW,
            "%": Operator.MOD,
            "*": Operator.MUL,
            "/": Operator.DIV,
            "//": Operator.FLOORDIV,
            "+": Operator.ADD,
            "-": Operator.SUB,
            "<<": Operator.LSHIFT,
            ">>": Operator.RSHIFT,
            "&": Operator.BITWISE_AND,
            "|": Operator.BITWISE_OR,
            "<": Operator.LT,
            "<=": Operator.LE,
            ">": Operator.GT,
            ">=": Operator.GE,
            "==": Operator.EQ,
            "!=": Operator.NEQ,
            "^": Operator.XOR,
            "&&": Operator.AND,
            "||": Operator.OR
        }
    def _replace_text(self, text:str):
        return text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
    
    def getOperator(self, op):
        if op in self.operators:
            return self.operators[op]
        else:
            raise ParseError(f"Operator {op} not supported")

    def visitScript(self, ctx: dAngrParser.ScriptContext):
        if ctx.QMARK() or ctx.HELP():
            args = []
            if ctx.identifier():
                cmd = self.visit(ctx.identifier())
                args = [cmd]
            return Script([DangrCommand("help",None, *args)],[]) # type: ignore
        else:
            statements = [self.visit(s) for s in ctx.statement()] if ctx.statement() else []
            definitions = [self.visit(c) for c in ctx.function_def()]
            statements = Statement.flatten(statements)
            return Script(statements, definitions)
    
    def visitStatement(self, ctx: dAngrParser.StatementContext):
        if ctx.assignment():
            return self.visit(ctx.assignment())
        elif ctx.control_flow():
            return self.visit(ctx.control_flow())
        elif ctx.expression():
            return self.visit(ctx.expression())
        elif ctx.ext_command():
            return self.visit(ctx.ext_command())
        elif ctx.static_var(): # static variable
            return VariableRef(self.visit(ctx.static_var().identifier()),True)
        raise ParseError(f"Invalid statement {ctx.getText()}")
    
    # def visitExpression(self, ctx: dAngrParser.ExpressionContext):
    #     if ctx.identifier():
    #         start = 0
    #         if ctx.DOT():
    #             package = ctx.identifier(0).getText()
    #             cmd =  ctx.identifier(1).getText()
    #             start = 3
    #         else:
    #             package = None
    #             cmd = ctx.identifier(0).getText()
    #             start = 1
    #         args = []
    #         kwargs  = {}
    #         if ctx.expression_part():
    #             children = ctx.children[start:]
    #             for i in range(0, len(children)):
    #                 #check if c is a terminalnode drop it
    #                 c = children[i]
    #                 if isinstance(c, TerminalNode):
    #                     continue

    #                 #if c is an identifier, it is a named argument
    #                 if isinstance(c, dAngrParser.IdentifierContext):
    #                     name = c.getText()
    #                     for j in range(i+1, len(children)):
    #                         if isinstance(children[j], TerminalNode):
    #                             continue
    #                         if isinstance(children[j], dAngrParser.IdentifierContext):
    #                             name = children[j].getText()
    #                         elif isinstance(children[j], dAngrParser.Expression_partContext):
    #                             kwargs[name] = self.visit(children[j])
    #                     break
    #                 else:
    #                     assert kwargs == {}
    #                     args.append(self.visit(c))
    #         return DangrCommand(cmd, package, *args, **kwargs)
    #     elif ctx.constraint():
    #         return self.visit(ctx.constraint())
    #     elif ctx.expression_part():
    #         return self.visit(ctx.expression_part(0))
    #     else:
    #         raise ParseError(f"Invalid expression {ctx.getText()}")
    
    # def visitConstraint(self, ctx: dAngrParser.ConstraintContext):
    #     if ctx.CIF(): # if constraint
    #         iif = self.visit(ctx.condition().expression())
    #         cthen = self.visit(ctx.expression_part(0))
    #         celse = self.visit(ctx.expression_part(1))
    #         return IfConstraint(iif, cthen, celse)
    #     else:
    #         raise ParseError(f"Invalid constraint {ctx.getText()}")

    def visitExpression(self, ctx: dAngrParser.ExpressionContext):
        if ctx.identifier():
            start = 0
            if ctx.DOT():
                package = ctx.identifier(0).getText()
                cmd =  ctx.identifier(1).getText()
                start = 3
            else:
                package = None
                cmd = ctx.identifier(0).getText()
                start = 1
            if ctx.DIV():
                cmd = "/" + cmd
            args = []
            kwargs  = {}
            if ctx.expression_part():
                children = ctx.children[start:]
                for i in range(0, len(children)):
                    #check if c is a terminalnode drop it
                    c = children[i]
                    if isinstance(c, TerminalNode):
                        continue

                    #if c is an identifier, it is a named argument
                    if isinstance(c, dAngrParser.IdentifierContext):
                        name = c.getText()
                        for j in range(i+1, len(children)):
                            if isinstance(children[j], TerminalNode):
                                continue
                            if isinstance(children[j], dAngrParser.IdentifierContext):
                                name = children[j].getText()
                            elif isinstance(children[j], dAngrParser.Expression_partContext):
                                kwargs[name] = self.visit(children[j])
                        break
                    else:
                        assert kwargs == {}
                        args.append(self.visit(c))
            return DangrCommand(cmd, package, *args, **kwargs)
        else:
            return self.visit(ctx.expression_part(0))
    def visitExpressionIf(self, ctx: dAngrParser.ExpressionIfContext):
        iif = self.visit(ctx.condition())
        cthen = self.visit(ctx.expression_part(0))
        celse = self.visit(ctx.expression_part(1))
        return IfConstraint(iif, cthen, celse)      
    def visitExpressionIn(self, ctx: dAngrParser.ExpressionInContext):
        return Inclusion(self.visit(ctx.expression_part(0)), self.visit(ctx.expression_part(1)))
    def visitExpressionAlt(self, ctx: dAngrParser.ExpressionAltContext):
        return self.visit(ctx.range_())
    def visitExpressionParenthesis(self, ctx: dAngrParser.ExpressionParenthesisContext):
        return self.visit(ctx.expression())
    def visitExpressionBool(self, ctx: dAngrParser.ExpressionBoolContext):
        return Literal(ctx.BOOL().getText() == "True")
    def visitExpressionObjectContext(self, ctx: dAngrParser.ExpressionObjectContext):
        return self.visit(ctx.object_())
    def visitExpressionRange(self, ctx: dAngrParser.ExpressionRangeContext):
        start = self.visit(ctx.expression_part(0))
        if len(ctx.expression_part())==1:
            return Range(start)
        end = self.visit(ctx.expression_part(1))
        if len(ctx.expression_part())==2:
            return Range(start, end)
        step = self.visit(ctx.expression_part(2))
        return Range(start, self.visit(ctx.expression_part(1)), step)
    def visitExpressionOperation(self, ctx: dAngrParser.ExpressionOperationContext):
        lhs = self.visit(ctx.object_())
        op = self.getOperator(ctx.operation().getText())
        rhs = self.visit(ctx.expression_part())
        return Comparison(lhs, op, rhs)
    def visitExpressionReference(self, ctx: dAngrParser.ExpressionReferenceContext):
        return self.visit(ctx.reference())
    
    def visitAssignment(self, ctx: dAngrParser.AssignmentContext):
        if ctx.static_var():
            var = VariableRef(self.visit(ctx.static_var().identifier()),True)
        else:
            var = self.visit(ctx.object_())

        val = self.visit(ctx.expression())
        return Assignment(var, val)
    
    def visitExt_command(self, ctx: dAngrParser.Ext_commandContext):
        if ctx.BANG():
            args = self.visit(ctx.py_basic_content())
            return PythonCommand(*args[0],**args[1])
        elif ctx.AMP():
            return self.visit(ctx.expression())
        elif ctx.DOLLAR():
            return self.visit(ctx.bash_content())
        raise ParseError(f"Invalid command {ctx.getText()}")
    
    def visitControl_flow(self, ctx: dAngrParser.Control_flowContext):
        if ctx.IF():
            return IfThenElse(self.visit(ctx.condition()), self.visit(ctx.body()), self.visit(ctx.else_().body()) if ctx.else_() else Body([]))
        elif ctx.WHILE():
            return WhileLoop(self.visit(ctx.condition()), self.visit(ctx.body()))
        elif ctx.FOR():
            index = None
            item = None
            if len(ctx.identifier())==2:
                index = VariableRef(self.visit(ctx.identifier(0)))
                item = VariableRef(self.visit(ctx.identifier(1)))
            else:
                item = VariableRef(self.visit(ctx.identifier(0)))
            return ForLoop(self.visit(ctx.iterable()), self.visit(ctx.body()),item, index)
        raise ParseError("Invalid control flow")    


    def visitFunction_def(self, ctx: dAngrParser.Function_defContext):
        name = ctx.identifier().getText()
        args = []
        if ctx.parameters():
            args = self.visit(ctx.parameters())
        body = self.visit(ctx.body())
        return CustomFunctionDefinition(name, args, body)
    
     
    def visitBody(self, ctx: dAngrParser.BodyContext):
        statements = [self.visit(s) for s in ctx.fstatement()] if ctx.fstatement() else []
        return Body(Statement.flatten(statements))
    
    def visitFstatement(self, ctx: dAngrParser.FstatementContext):
        if ctx.BREAK():
            return BREAK
        elif ctx.CONTINUE():
            return CONTINUE
        elif ctx.expression():
            return self.visit(ctx.expression()) # TODO: deal with return
        elif ctx.statement():
            return self.visit(ctx.statement())

    def visitIterable(self, ctx: dAngrParser.IterableContext):
        # if not ctx.LPAREN():
        return self.visit(ctx.expression())
        # else:
        
    def visitParameters(self, ctx: dAngrParser.ParametersContext):
        return [ArgumentSpec(p.getText())for p in ctx.identifier()]

    def visitCondition(self, ctx: dAngrParser.ConditionContext):
        return self.visit(ctx.expression())
    
#OBJECTS
    def visitIDObject(self, ctx: dAngrParser.IDObjectContext):
        v = VariableRef(self.visit(ctx.identifier()))
        if ctx.BANG():
            return DangrCommand("evaluate", None, v)
        return v
    def visitNumericObject(self, ctx: dAngrParser.NumericObjectContext):
        if ctx.DASH():
            return Negate(self.visit(ctx.numeric()))
        return self.visit(ctx.numeric())
    
    def visitBoolObject(self, ctx: dAngrParser.BoolObjectContext):
        return Literal(ctx.BOOL().getText() == "True")
    def visitReferenceObject(self, ctx: dAngrParser.ReferenceObjectContext):
        return self.visit(ctx.reference())
    def visitPropertyObject(self, ctx: dAngrParser.PropertyObjectContext):
        o = self.visit(ctx.object_())
        return Property(o, ctx.identifier().getText())
    
    def visitIndexedPropertyObject(self, ctx: dAngrParser.IndexedPropertyObjectContext):
        o = self.visit(ctx.object_())
        index = self.visit(ctx.index())
        return IndexedProperty(o, index)
    def visitSliceStartEndObject(self, ctx: dAngrParser.SliceStartEndObjectContext):
        o = self.visit(ctx.object_())
        start = self.visit(ctx.index(0))
        if len(ctx.index())>1:
            end = self.visit(ctx.index(1))
        else:
            end = -1
        return Slice(o, start, end)
    def visitSlideStartLengthObject(self, ctx: dAngrParser.SlideStartLengthObjectContext):
        o = self.visit(ctx.object_())
        start = self.visit(ctx.index(0))
        length = self.visit(ctx.index(1))
        return Slice(o, start, Comparison(start, Operator.ADD, length))
    
    def visitListObject(self, ctx: dAngrParser.ListObjectContext):
        objs = [self.visit(o) for o in ctx.object_()]
        return Listing(objs)
    def visitDictionaryObject(self, ctx: dAngrParser.DictionaryObjectContext):
        l = len(ctx.object_())
        d = {}
        for i in range(l):
            d[ctx.STRING(i).getText().strip("'\"")] = self.visit(ctx.object_(i))
        return Dictionary(d)
    def visitStringObject(self, ctx: dAngrParser.StringObjectContext):
        return Literal(self._replace_text(ctx.STRING().getText()[1:-1]))
    def visitBinaryStringObject(self, ctx: dAngrParser.BinaryStringObjectContext):
        return Literal(parse_binary_string(ctx.BINARY_STRING().getText()))
#END OBJECTS
       
    def visitIndex(self, ctx: dAngrParser.IndexContext):
        if ctx.DASH():
            return Negate(self.visit(ctx.expression()))
        else:    
            return self.visit(ctx.expression())
    
    def visitIdentifier(self, ctx: dAngrParser.IdentifierContext):
        return Literal(ctx.getText())
    
    def visitNumeric(self, ctx: dAngrParser.NumericContext):
        return Literal(int(ctx.NUMBERS().getText()) if ctx.NUMBERS() else int(ctx.HEX_NUMBERS().getText(), 16))
    
   
    def _isSTRING(self, ctx):
        if isinstance(ctx, TerminalNode):
            return False
        c =ctx.getTokens(dAngrParser.STRING)
        if len(c) == 1:
            return True
        return (self._isSTRING(ctx.children[0]) if len(ctx.children) == 1 else False)

    def visitPy_basic_content(self, ctx: dAngrParser.Py_basic_contentContext):
        name = ctx.identifier().getText()
        args = []
        kwargs = {}
        for c in ctx.children[1:]:
            if isinstance(c, dAngrParser.Py_contentContext):
                py = self.visit(c)
                args.extend(py.cmds)
                kwargs.update(py.kwargs)
            else:
                args.append(Literal(c.getText()))
        return [name]+args, kwargs
    def visitPy_content(self, ctx: dAngrParser.Py_contentContext):

        args = []
        kwargs = {}
        for c in ctx.children:
            if isinstance(c, dAngrParser.RangeContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.AnythingContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.ReferenceContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.Py_contentContext):
                py:PythonCommand = self.visit(c)
                args.extend(py.cmds)
                kwargs.update(py.kwargs)
            else:
                args.append(Literal(c.getText()))
        return PythonCommand(*args)
    
    def visitReference(self, ctx: dAngrParser.ReferenceContext):
        if ctx.MEM_DB():
            size = None
            if len(ctx.index()) == 2:
                size = self.visit(ctx.index(1))
            m = Memory(self.visit(ctx.index(0)), size)
            if ctx.BANG():
                return DangrCommand("evaluate", None, m)
            return m
        elif ctx.VARS_DB():
            r = ReferenceObject.createNamedObject(ctx.VARS_DB().getText(), self.visit(ctx.identifier()))
            if ctx.BANG():
                return DangrCommand("evaluate", None, r)
            return r
        elif ctx.REG_DB():
            r = ReferenceObject.createNamedObject(ctx.REG_DB().getText(), self.visit(ctx.identifier()))
            if ctx.BANG():
                return DangrCommand("evaluate", None, r)
            return r
        elif ctx.SYM_DB():
            r = ReferenceObject.createNamedObject(ctx.SYM_DB().getText(), self.visit(ctx.identifier()))
            if ctx.BANG():
                return DangrCommand("evaluate", None, r)
            return r
        elif ctx.STATE():
            return StateObject()
        else:
            raise ParseError(f"Invalid reference {ctx.getText()}")
        
    
    def visitBash_content(self, ctx: dAngrParser.Bash_contentContext):
        args = []
        for c in ctx.children:
            if isinstance(c, dAngrParser.RangeContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.AnythingContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.ReferenceContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.Bash_contentContext):
                ba:BashCommand = self.visit(c)
                args.extend(ba.cmds)
            else:
                args.append(Literal(c.getText()))
        return BashCommand(*args)
    
    def visitSymbol(self, ctx: dAngrParser.SymbolContext):
        return Literal(ctx.getText())
    def visitAnything(self, ctx: dAngrParser.AnythingContext):
        return Literal(ctx.getText())

    def visitRange(self, ctx: dAngrParser.RangeContext):
        if ctx.bash_range():
            return self.visit(ctx.bash_range().bash_content())
        elif ctx.python_range():
            return self.visit(ctx.python_range().py_content())
        else:
            return self.visit(ctx.dangr_range().expression())