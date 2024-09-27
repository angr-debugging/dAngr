
from typing import List, Sequence

from antlr4 import TerminalNode
from dAngr.exceptions import ParseError, ValueError
from dAngr.cli.grammar.antlr.dAngrParser import dAngrParser
from dAngr.cli.grammar.antlr.dAngrVisitor import dAngrVisitor
from dAngr.cli.grammar.statements import Assignment,  Statement,  Object, VariableRef
from dAngr.cli.grammar.control_flow import IfThenElse, WhileLoop, ForLoop
from dAngr.cli.grammar.script import Script, Body
from dAngr.cli.grammar.definitions import CustomFunctionDefinition
from dAngr.cli.grammar.expressions import DangrCommand, Dictionary, Listing, Memory, PythonCommand, BashCommand, Comparison, Literal, Property, IndexedProperty, Range, ReferenceObject, Slice
from dAngr.utils.utils import parse_binary_string


class dAngrVisitor_(dAngrVisitor):
    def __init__(self):
        self.operators = {
            "==" : "__eq__",
            "!=" : "__ne__",
            "<" : "__lt__",
            "<=" : "__le__",
            ">" : "__gt__",
            ">=" : "__ge__",
            "+" : "__add__",
            "-" : "__sub__",
            "*" : "__mul__",
            "/" : "__truediv__",
            "%" : "__mod__",
            "**" : "__pow__"
        }

    def getOperator(self, op):
        if op in self.operators:
            return self.operators[op]
        else:
            raise ParseError(f"Operator {op} not supported")
    # def getFullString(self, ctx, from_token, to_token):
    #     start = from_token
    #     stop = to_token
        
    #     # Assuming you have access to the token stream from the parser
    #     token_stream = ctx.parser.getTokenStream()  # CommonTokenStream

    #     # Get the tokens between start and stop (excluding hidden tokens)
    #     tokens = token_stream.getTokens(start.tokenIndex, stop.tokenIndex)

    #     full_text = []

    #     # Loop through each token
    #     for token in tokens:
    #         # Get hidden tokens before the current token (like whitespaces)
    #         hidden_tokens = token_stream.getHiddenTokensToLeft(token.tokenIndex)

    #         # Append hidden tokens (whitespace, comments) to the result
    #         if hidden_tokens:
    #             for hidden_token in hidden_tokens:
    #                 full_text.append(hidden_token.text)

    #         # Append the actual token text
    #         full_text.append(token.text)

    #     # Join the list into a single string and return it
    #     return ''.join(full_text)

    def visitScript(self, ctx: dAngrParser.ScriptContext):
        if ctx.QMARK() or ctx.HELP():
            args = []
            if ctx.identifier():
                cmd = Literal(ctx.identifier().getText())
                args = [cmd]
            return Script([DangrCommand("help", *args)],[]) # type: ignore
        else:
            statements = [self.visit(s) for s in ctx.statement()] if ctx.statement() else []
            definitions = [self.visit(c) for c in ctx.function_def()]
            statements = Statement.flatten(statements)
            return Script(statements, definitions)
    
    # def visitDangr(self, ctx: dAngrParser.DangrContext):
    #     if ctx.range_():
    #         return self.visit(ctx.range_())
    #     elif ctx.statement():
    #         return self.visit(ctx.statement())
    #     raise ValueError(f"Invalid command {ctx.getText()}")

    def visitStatement(self, ctx: dAngrParser.StatementContext):
        if ctx.dangr_command():
            return self.visit(ctx.dangr_command())
        elif ctx.assignment():
            return self.visit(ctx.assignment())
        elif ctx.control_flow():
            return self.visit(ctx.control_flow())
        elif ctx.expression():
            return self.visit(ctx.expression())
        elif ctx.ext_command():
            return self.visit(ctx.ext_command())
        raise ParseError(f"Invalid statement {ctx.getText()}")
    
    def visitExpression(self, ctx: dAngrParser.ExpressionContext):
        if ctx.range_():
            return self.visit(ctx.range_())
        elif ctx.object_():
            return self.visit(ctx.object_())
        else:
            return self.visit(ctx.expression_part())
    def visitExpression_part(self, ctx: dAngrParser.Expression_partContext):
        if ctx.object_():
            lhs = self.visit(ctx.object_())
            if ctx.operation():
                op =  self.getOperator(ctx.operation().getText())
                rhs = self.visit(ctx.expression_part())
                return Comparison(lhs, op, rhs)
            else:
                return lhs
        else:
            return self.visit(ctx.range_())

    def visitAssignment(self, ctx: dAngrParser.AssignmentContext):
        var = self.visit(ctx.object_())
        val = self.visit(ctx.expression())
        return Assignment(var, val)
    
    def visitDangr_command(self, ctx: dAngrParser.Dangr_commandContext):
        if ctx.add_constraint():
            return self.visit(ctx.add_constraint())
        else:
            cmd = ctx.identifier(0).getText()
            args = []
            kwargs  = {}
            if ctx.expression():
                children = ctx.children[1:]
                for i in range(0, len(children)):
                    #check if c is a terminalnode drop it
                    c = children[i]
                    if isinstance(c, TerminalNode):
                        continue
                    #if c is an identifier, it is a named argument
                    if isinstance(c, dAngrParser.IdentifierContext):
                        kwargs[c.getText()] = self.visit(children[i+2])
                        i+=1
                    else:
                        assert kwargs == {}
                        args.append(self.visit(c))
            return DangrCommand(cmd, *args, **kwargs)
    
    def visitAdd_constraint(self, ctx: dAngrParser.Add_constraintContext):
        cmd = "add_constraint"
        target = self.visit(ctx.object_())
        op = self.getOperator(ctx.operation().getText())
        constraint = self.visit(ctx.expression())
        arg = Comparison(target,op, constraint)
        return DangrCommand(cmd, arg)

    def visitExt_command(self, ctx: dAngrParser.Ext_commandContext):
        if ctx.BANG():
            # name,args,kwargs = self.visit(ctx.py_content())
            # return PythonCommand(name,*args,**kwargs)
            return PythonCommand(*self.visit(ctx.py_content()))
        elif ctx.AMP():
            return self.visit(ctx.dangr_command())
        elif ctx.DOLLAR():
            return BashCommand(*self.visit(ctx.bash_content()))
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
                index = VariableRef(ctx.identifier(0).getText())
                item = VariableRef(ctx.identifier(1).getText())
            else:
                item = VariableRef(ctx.identifier(0).getText())
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
        statements = [self.visit(s) for s in ctx.statement()] if ctx.statement() else []
        return Body(Statement.flatten(statements))

    def visitIterable(self, ctx: dAngrParser.IterableContext):
        if ctx.object_():
            return self.visit(ctx.object_())
        else:
            start = self.visit(ctx.numeric(0))
            if len(ctx.numeric()) == 1:
                return Range(start)
            end = self.visit(ctx.numeric(1))
            return Range(start, end)
        
    def visitParameters(self, ctx: dAngrParser.ParametersContext):
        return [p.getText() for p in ctx.identifier()]

    def visitCondition(self, ctx: dAngrParser.ConditionContext):
        return self.visit(ctx.expression())
        
    def visitObject(self, ctx: dAngrParser.ObjectContext):
        
        if ctx.MEM_DB():
            size = int(ctx.NUMBERS().getText()) if ctx.NUMBERS() else 0
            return Memory(self.visit(ctx.numeric(0)), size)
        elif ctx.VARS_DB():
            return ReferenceObject.createNamedObject(ctx.VARS_DB().getText(), ctx.identifier().getText())
        elif ctx.REG_DB():
            return ReferenceObject.createNamedObject(ctx.REG_DB().getText(), ctx.identifier().getText())
        elif ctx.SYM_DB():
            return ReferenceObject.createNamedObject(ctx.SYM_DB().getText(), ctx.identifier().getText())
        elif ctx.NUMBERS():
            return Literal(int(ctx.NUMBERS().getText()))
        elif ctx.HEX_NUMBERS():
            return Literal(int(ctx.HEX_NUMBERS().getText(), 16))
        elif ctx.STRING():
            if ctx.BRACE(): # Dictionary
                l = len(ctx.STRING())
                d = {}
                for i in range(l):
                    d[ctx.STRING(i).getText()[1:-1]] = self.visit(ctx.object_(i))
                return Dictionary(d)
            else:
                return Literal(ctx.getText()[1:-1])
        elif ctx.BINARY_STRING():
            return Literal(parse_binary_string(ctx.BINARY_STRING().getText()))
        elif ctx.BOOL():
            return Literal(ctx.BOOL().getText() == "True")
        elif ctx.identifier() and not ctx.object_():
            return VariableRef(ctx.identifier().getText())
        elif ctx.object_():
            o = self.visit(ctx.object_(0))
            if ctx.DOT(): # Property
                return Property(o, ctx.identifier().getText())
            elif ctx.BRA():
                if ctx.index(): # IndexedProperty
                    index = self.visit(ctx.index())
                    return IndexedProperty(o, index)
                elif ctx.numeric():
                    if ctx.COLON():
                        start =  self.visit(ctx.NUMBERS()) 
                        end = self.visit(ctx.numeric(0))
                        return Slice(o,start, int(ctx.NUMBERS()[1].getText()))
                    elif ctx.ARROW():
                        start = int(ctx.NUMBERS().getText())
                        end = start + int(ctx.NUMBERS(1).getText())
                        return Slice(o,start, end)
                elif ctx.COMMA(): # Listing
                    lst = [self.visit(o) for o in ctx.object_()]
                    return Listing(lst)
        raise ParseError("Invalid object")
    

    # def visitReference(self, ctx: dAngrParser.ReferenceContext):
       
    def visitIndex(self, ctx: dAngrParser.IndexContext):
        if ctx.identifier():
            return ctx.identifier().getText()
        elif ctx.numeric():
            return self.visit(ctx.numeric())
        raise ParseError(f"Invalid index {ctx.getText()}")
    
    def visitIdentifier(self, ctx: dAngrParser.IdentifierContext):
        raise ParseError(f"Invalid identifier {ctx.getText()}")
    
    def visitNumeric(self, ctx: dAngrParser.NumericContext):
        return int(ctx.NUMBERS().getText()) if ctx.NUMBERS() else int(ctx.HEX_NUMBERS().getText(), 16)
    
    # FROM Ranges
    # def visitContent(self, ctx: dAngrParser.ContentContext):
    #     content = []
    #     i = 0
    #     if ctx.identifier():
    #         content.append(Literal(ctx.identifier().getText()))
    #         i=1
    #     for x in range(i,len(ctx.children)) :
    #         token = ctx.children[x]
    #         if isinstance(token, dAngrParser.SymbolContext):
    #             content.append(Literal(token.getText())) # type: ignore
    #         elif isinstance(token, dAngrParser.ObjectContext):
    #             if token.STRING():
    #                 content.append(Literal(token.getText())) # dont ignore quotes
    #             else:
    #                 content.append(self.visit(token))
    #         elif isinstance(token, TerminalNode): #WS
    #             content.append(Literal(token.getText())) # type: ignore
    #         elif isinstance(token, dAngrParser.OperationContext):
    #             content.append(self.visit(token))
    #         elif isinstance(token, dAngrParser.Expression_partContext):
    #             content.append(self.visit(token))
    #     #merge consecutive literals
    #     cc = []
    #     for c in content:
    #         if cc and isinstance(cc[-1], Literal) and isinstance(c, Literal):
    #             cc[-1] = Literal(cc[-1].value + c.value)
    #         else:
    #             cc.append(c)
    #     return cc
   
    def _isSTRING(self, ctx):
        if isinstance(ctx, TerminalNode):
            return False
        c =ctx.getTokens(dAngrParser.STRING)
        if len(c) == 1:
            return True
        return (self._isSTRING(ctx.children[0]) if len(ctx.children) == 1 else False)

    def visitPy_content(self, ctx: dAngrParser.Py_contentContext):
        name = ctx.identifier().getText()
        args = []
        for c in ctx.children[1:]:
            if isinstance(c, dAngrParser.ReferenceContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.RangeContext):
                args.append(self.visit(c))
            else:
                args.append(Literal(c.getText()))
        return [name]+args
    def visitReference(self, ctx: dAngrParser.ReferenceContext):
        if ctx.MEM_DB():
            size = int(ctx.NUMBERS().getText()) if ctx.NUMBERS() else 0
            return Memory(self.visit(ctx.numeric(0)), size)
        elif ctx.VARS_DB():
            return ReferenceObject.createNamedObject(ctx.VARS_DB().getText(), ctx.identifier().getText())
        elif ctx.REG_DB():
            return ReferenceObject.createNamedObject(ctx.REG_DB().getText(), ctx.identifier().getText())
        elif ctx.SYM_DB():
            return ReferenceObject.createNamedObject(ctx.SYM_DB().getText(), ctx.identifier().getText())
        
        # args = []
        # kwargs = {}
        # name = ctx.identifier().getText()
        # for c in ctx.children[1:]:
        #     if self._isSTRING(c):
        #         args.append(Literal(c.getText()))
        #         continue
        #     if isinstance(c, TerminalNode):
        #         a = Literal(c.getText()) # type: ignore
        #     else:
        #         a = self.visit(c)
        #     if isinstance(a, dict):
        #         kwargs.update(a)
        #     else:
        #         args.append(a)
        # return name, args, kwargs
    
    # def visitNamed_arg(self, ctx: dAngrParser.Named_argContext):
    #     if ctx.identifier():
    #         return {ctx.identifier().getText() : self.visit(ctx.expression())}
    #     else:
    #         return self.visit(ctx.expression())
    
    def visitBash_content(self, ctx: dAngrParser.Bash_contentContext):
        name = ctx.identifier().getText()
        args = []
        for c in ctx.children[1:]:
            if isinstance(c, dAngrParser.ReferenceContext):
                args.append(self.visit(c))
            elif isinstance(c, dAngrParser.RangeContext):
                args.append(self.visit(c))
            else:
                args.append(Literal(c.getText()))
        return [name]+args
    
    def visitSymbol(self, ctx: dAngrParser.SymbolContext):
        return Literal(ctx.getText())
    def visitAnything(self, ctx: dAngrParser.AnythingContext):
        return Literal(ctx.getText())

    def visitRange(self, ctx: dAngrParser.RangeContext):
        if ctx.bash_range():
            return BashCommand(*self.visit(ctx.bash_range().bash_content()))
        elif ctx.python_range():
            # name, args, kwargs = self.visit(ctx.python_range().py_content())
            # return PythonCommand(name, *args, **kwargs)
            return PythonCommand(*self.visit(ctx.python_range().py_content()))
        else:
            return self.visit(ctx.dangr_range().statement())