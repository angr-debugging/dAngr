# Generated from /workspaces/dAngr/src/dAngr/cli/grammar/dAngr.g4 by ANTLR 4.13.1
from antlr4 import *
if "." in __name__:
    from .dAngrParser import dAngrParser
else:
    from dAngrParser import dAngrParser

# This class defines a complete generic visitor for a parse tree produced by dAngrParser.

class dAngrVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by dAngrParser#script.
    def visitScript(self, ctx:dAngrParser.ScriptContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#statement.
    def visitStatement(self, ctx:dAngrParser.StatementContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#expression.
    def visitExpression(self, ctx:dAngrParser.ExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#expression_part.
    def visitExpression_part(self, ctx:dAngrParser.Expression_partContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#assignment.
    def visitAssignment(self, ctx:dAngrParser.AssignmentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#dangr_command.
    def visitDangr_command(self, ctx:dAngrParser.Dangr_commandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#add_constraint.
    def visitAdd_constraint(self, ctx:dAngrParser.Add_constraintContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ext_command.
    def visitExt_command(self, ctx:dAngrParser.Ext_commandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#control_flow.
    def visitControl_flow(self, ctx:dAngrParser.Control_flowContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#else_.
    def visitElse_(self, ctx:dAngrParser.Else_Context):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#function_def.
    def visitFunction_def(self, ctx:dAngrParser.Function_defContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#body.
    def visitBody(self, ctx:dAngrParser.BodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#iterable.
    def visitIterable(self, ctx:dAngrParser.IterableContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#parameters.
    def visitParameters(self, ctx:dAngrParser.ParametersContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#condition.
    def visitCondition(self, ctx:dAngrParser.ConditionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#operation.
    def visitOperation(self, ctx:dAngrParser.OperationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#py_content.
    def visitPy_content(self, ctx:dAngrParser.Py_contentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#reference.
    def visitReference(self, ctx:dAngrParser.ReferenceContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#bash_content.
    def visitBash_content(self, ctx:dAngrParser.Bash_contentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#index.
    def visitIndex(self, ctx:dAngrParser.IndexContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#identifier.
    def visitIdentifier(self, ctx:dAngrParser.IdentifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#numeric.
    def visitNumeric(self, ctx:dAngrParser.NumericContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#object.
    def visitObject(self, ctx:dAngrParser.ObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#range.
    def visitRange(self, ctx:dAngrParser.RangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#bash_range.
    def visitBash_range(self, ctx:dAngrParser.Bash_rangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#dangr_range.
    def visitDangr_range(self, ctx:dAngrParser.Dangr_rangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#python_range.
    def visitPython_range(self, ctx:dAngrParser.Python_rangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#anything.
    def visitAnything(self, ctx:dAngrParser.AnythingContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#symbol.
    def visitSymbol(self, ctx:dAngrParser.SymbolContext):
        return self.visitChildren(ctx)



del dAngrParser