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


    # Visit a parse tree produced by dAngrParser#ExpressionRange.
    def visitExpressionRange(self, ctx:dAngrParser.ExpressionRangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionIn.
    def visitExpressionIn(self, ctx:dAngrParser.ExpressionInContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionObject.
    def visitExpressionObject(self, ctx:dAngrParser.ExpressionObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionBool.
    def visitExpressionBool(self, ctx:dAngrParser.ExpressionBoolContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionReference.
    def visitExpressionReference(self, ctx:dAngrParser.ExpressionReferenceContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionIf.
    def visitExpressionIf(self, ctx:dAngrParser.ExpressionIfContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionAlt.
    def visitExpressionAlt(self, ctx:dAngrParser.ExpressionAltContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionParenthesis.
    def visitExpressionParenthesis(self, ctx:dAngrParser.ExpressionParenthesisContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ExpressionOperation.
    def visitExpressionOperation(self, ctx:dAngrParser.ExpressionOperationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#assignment.
    def visitAssignment(self, ctx:dAngrParser.AssignmentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#static_var.
    def visitStatic_var(self, ctx:dAngrParser.Static_varContext):
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


    # Visit a parse tree produced by dAngrParser#fstatement.
    def visitFstatement(self, ctx:dAngrParser.FstatementContext):
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


    # Visit a parse tree produced by dAngrParser#py_basic_content.
    def visitPy_basic_content(self, ctx:dAngrParser.Py_basic_contentContext):
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


    # Visit a parse tree produced by dAngrParser#SlideStartLengthObject.
    def visitSlideStartLengthObject(self, ctx:dAngrParser.SlideStartLengthObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ReferenceObject.
    def visitReferenceObject(self, ctx:dAngrParser.ReferenceObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#BinaryStringObject.
    def visitBinaryStringObject(self, ctx:dAngrParser.BinaryStringObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#ListObject.
    def visitListObject(self, ctx:dAngrParser.ListObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#IndexedPropertyObject.
    def visitIndexedPropertyObject(self, ctx:dAngrParser.IndexedPropertyObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#DictionaryObject.
    def visitDictionaryObject(self, ctx:dAngrParser.DictionaryObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#NumericObject.
    def visitNumericObject(self, ctx:dAngrParser.NumericObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#SliceStartEndObject.
    def visitSliceStartEndObject(self, ctx:dAngrParser.SliceStartEndObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#StringObject.
    def visitStringObject(self, ctx:dAngrParser.StringObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#IDObject.
    def visitIDObject(self, ctx:dAngrParser.IDObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#PropertyObject.
    def visitPropertyObject(self, ctx:dAngrParser.PropertyObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#BoolObject.
    def visitBoolObject(self, ctx:dAngrParser.BoolObjectContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by dAngrParser#special_words.
    def visitSpecial_words(self, ctx:dAngrParser.Special_wordsContext):
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