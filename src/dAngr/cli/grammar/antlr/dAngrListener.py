# Generated from /workspaces/dAngr/src/dAngr/cli/grammar/dAngr.g4 by ANTLR 4.13.1
from antlr4 import *
if "." in __name__:
    from .dAngrParser import dAngrParser
else:
    from dAngrParser import dAngrParser

# This class defines a complete listener for a parse tree produced by dAngrParser.
class dAngrListener(ParseTreeListener):

    # Enter a parse tree produced by dAngrParser#script.
    def enterScript(self, ctx:dAngrParser.ScriptContext):
        pass

    # Exit a parse tree produced by dAngrParser#script.
    def exitScript(self, ctx:dAngrParser.ScriptContext):
        pass


    # Enter a parse tree produced by dAngrParser#statement.
    def enterStatement(self, ctx:dAngrParser.StatementContext):
        pass

    # Exit a parse tree produced by dAngrParser#statement.
    def exitStatement(self, ctx:dAngrParser.StatementContext):
        pass


    # Enter a parse tree produced by dAngrParser#expression.
    def enterExpression(self, ctx:dAngrParser.ExpressionContext):
        pass

    # Exit a parse tree produced by dAngrParser#expression.
    def exitExpression(self, ctx:dAngrParser.ExpressionContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionRange.
    def enterExpressionRange(self, ctx:dAngrParser.ExpressionRangeContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionRange.
    def exitExpressionRange(self, ctx:dAngrParser.ExpressionRangeContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionIn.
    def enterExpressionIn(self, ctx:dAngrParser.ExpressionInContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionIn.
    def exitExpressionIn(self, ctx:dAngrParser.ExpressionInContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionObject.
    def enterExpressionObject(self, ctx:dAngrParser.ExpressionObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionObject.
    def exitExpressionObject(self, ctx:dAngrParser.ExpressionObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionBool.
    def enterExpressionBool(self, ctx:dAngrParser.ExpressionBoolContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionBool.
    def exitExpressionBool(self, ctx:dAngrParser.ExpressionBoolContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionReference.
    def enterExpressionReference(self, ctx:dAngrParser.ExpressionReferenceContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionReference.
    def exitExpressionReference(self, ctx:dAngrParser.ExpressionReferenceContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionIf.
    def enterExpressionIf(self, ctx:dAngrParser.ExpressionIfContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionIf.
    def exitExpressionIf(self, ctx:dAngrParser.ExpressionIfContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionAlt.
    def enterExpressionAlt(self, ctx:dAngrParser.ExpressionAltContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionAlt.
    def exitExpressionAlt(self, ctx:dAngrParser.ExpressionAltContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionParenthesis.
    def enterExpressionParenthesis(self, ctx:dAngrParser.ExpressionParenthesisContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionParenthesis.
    def exitExpressionParenthesis(self, ctx:dAngrParser.ExpressionParenthesisContext):
        pass


    # Enter a parse tree produced by dAngrParser#ExpressionOperation.
    def enterExpressionOperation(self, ctx:dAngrParser.ExpressionOperationContext):
        pass

    # Exit a parse tree produced by dAngrParser#ExpressionOperation.
    def exitExpressionOperation(self, ctx:dAngrParser.ExpressionOperationContext):
        pass


    # Enter a parse tree produced by dAngrParser#assignment.
    def enterAssignment(self, ctx:dAngrParser.AssignmentContext):
        pass

    # Exit a parse tree produced by dAngrParser#assignment.
    def exitAssignment(self, ctx:dAngrParser.AssignmentContext):
        pass


    # Enter a parse tree produced by dAngrParser#static_var.
    def enterStatic_var(self, ctx:dAngrParser.Static_varContext):
        pass

    # Exit a parse tree produced by dAngrParser#static_var.
    def exitStatic_var(self, ctx:dAngrParser.Static_varContext):
        pass


    # Enter a parse tree produced by dAngrParser#ext_command.
    def enterExt_command(self, ctx:dAngrParser.Ext_commandContext):
        pass

    # Exit a parse tree produced by dAngrParser#ext_command.
    def exitExt_command(self, ctx:dAngrParser.Ext_commandContext):
        pass


    # Enter a parse tree produced by dAngrParser#control_flow.
    def enterControl_flow(self, ctx:dAngrParser.Control_flowContext):
        pass

    # Exit a parse tree produced by dAngrParser#control_flow.
    def exitControl_flow(self, ctx:dAngrParser.Control_flowContext):
        pass


    # Enter a parse tree produced by dAngrParser#else_.
    def enterElse_(self, ctx:dAngrParser.Else_Context):
        pass

    # Exit a parse tree produced by dAngrParser#else_.
    def exitElse_(self, ctx:dAngrParser.Else_Context):
        pass


    # Enter a parse tree produced by dAngrParser#function_def.
    def enterFunction_def(self, ctx:dAngrParser.Function_defContext):
        pass

    # Exit a parse tree produced by dAngrParser#function_def.
    def exitFunction_def(self, ctx:dAngrParser.Function_defContext):
        pass


    # Enter a parse tree produced by dAngrParser#body.
    def enterBody(self, ctx:dAngrParser.BodyContext):
        pass

    # Exit a parse tree produced by dAngrParser#body.
    def exitBody(self, ctx:dAngrParser.BodyContext):
        pass


    # Enter a parse tree produced by dAngrParser#fstatement.
    def enterFstatement(self, ctx:dAngrParser.FstatementContext):
        pass

    # Exit a parse tree produced by dAngrParser#fstatement.
    def exitFstatement(self, ctx:dAngrParser.FstatementContext):
        pass


    # Enter a parse tree produced by dAngrParser#iterable.
    def enterIterable(self, ctx:dAngrParser.IterableContext):
        pass

    # Exit a parse tree produced by dAngrParser#iterable.
    def exitIterable(self, ctx:dAngrParser.IterableContext):
        pass


    # Enter a parse tree produced by dAngrParser#parameters.
    def enterParameters(self, ctx:dAngrParser.ParametersContext):
        pass

    # Exit a parse tree produced by dAngrParser#parameters.
    def exitParameters(self, ctx:dAngrParser.ParametersContext):
        pass


    # Enter a parse tree produced by dAngrParser#condition.
    def enterCondition(self, ctx:dAngrParser.ConditionContext):
        pass

    # Exit a parse tree produced by dAngrParser#condition.
    def exitCondition(self, ctx:dAngrParser.ConditionContext):
        pass


    # Enter a parse tree produced by dAngrParser#operation.
    def enterOperation(self, ctx:dAngrParser.OperationContext):
        pass

    # Exit a parse tree produced by dAngrParser#operation.
    def exitOperation(self, ctx:dAngrParser.OperationContext):
        pass


    # Enter a parse tree produced by dAngrParser#py_basic_content.
    def enterPy_basic_content(self, ctx:dAngrParser.Py_basic_contentContext):
        pass

    # Exit a parse tree produced by dAngrParser#py_basic_content.
    def exitPy_basic_content(self, ctx:dAngrParser.Py_basic_contentContext):
        pass


    # Enter a parse tree produced by dAngrParser#py_content.
    def enterPy_content(self, ctx:dAngrParser.Py_contentContext):
        pass

    # Exit a parse tree produced by dAngrParser#py_content.
    def exitPy_content(self, ctx:dAngrParser.Py_contentContext):
        pass


    # Enter a parse tree produced by dAngrParser#bash_content.
    def enterBash_content(self, ctx:dAngrParser.Bash_contentContext):
        pass

    # Exit a parse tree produced by dAngrParser#bash_content.
    def exitBash_content(self, ctx:dAngrParser.Bash_contentContext):
        pass


    # Enter a parse tree produced by dAngrParser#reference.
    def enterReference(self, ctx:dAngrParser.ReferenceContext):
        pass

    # Exit a parse tree produced by dAngrParser#reference.
    def exitReference(self, ctx:dAngrParser.ReferenceContext):
        pass


    # Enter a parse tree produced by dAngrParser#index.
    def enterIndex(self, ctx:dAngrParser.IndexContext):
        pass

    # Exit a parse tree produced by dAngrParser#index.
    def exitIndex(self, ctx:dAngrParser.IndexContext):
        pass


    # Enter a parse tree produced by dAngrParser#identifier.
    def enterIdentifier(self, ctx:dAngrParser.IdentifierContext):
        pass

    # Exit a parse tree produced by dAngrParser#identifier.
    def exitIdentifier(self, ctx:dAngrParser.IdentifierContext):
        pass


    # Enter a parse tree produced by dAngrParser#numeric.
    def enterNumeric(self, ctx:dAngrParser.NumericContext):
        pass

    # Exit a parse tree produced by dAngrParser#numeric.
    def exitNumeric(self, ctx:dAngrParser.NumericContext):
        pass


    # Enter a parse tree produced by dAngrParser#SlideStartLengthObject.
    def enterSlideStartLengthObject(self, ctx:dAngrParser.SlideStartLengthObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#SlideStartLengthObject.
    def exitSlideStartLengthObject(self, ctx:dAngrParser.SlideStartLengthObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#ReferenceObject.
    def enterReferenceObject(self, ctx:dAngrParser.ReferenceObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#ReferenceObject.
    def exitReferenceObject(self, ctx:dAngrParser.ReferenceObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#BinaryStringObject.
    def enterBinaryStringObject(self, ctx:dAngrParser.BinaryStringObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#BinaryStringObject.
    def exitBinaryStringObject(self, ctx:dAngrParser.BinaryStringObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#ListObject.
    def enterListObject(self, ctx:dAngrParser.ListObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#ListObject.
    def exitListObject(self, ctx:dAngrParser.ListObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#IndexedPropertyObject.
    def enterIndexedPropertyObject(self, ctx:dAngrParser.IndexedPropertyObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#IndexedPropertyObject.
    def exitIndexedPropertyObject(self, ctx:dAngrParser.IndexedPropertyObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#DictionaryObject.
    def enterDictionaryObject(self, ctx:dAngrParser.DictionaryObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#DictionaryObject.
    def exitDictionaryObject(self, ctx:dAngrParser.DictionaryObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#NumericObject.
    def enterNumericObject(self, ctx:dAngrParser.NumericObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#NumericObject.
    def exitNumericObject(self, ctx:dAngrParser.NumericObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#SliceStartEndObject.
    def enterSliceStartEndObject(self, ctx:dAngrParser.SliceStartEndObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#SliceStartEndObject.
    def exitSliceStartEndObject(self, ctx:dAngrParser.SliceStartEndObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#StringObject.
    def enterStringObject(self, ctx:dAngrParser.StringObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#StringObject.
    def exitStringObject(self, ctx:dAngrParser.StringObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#IDObject.
    def enterIDObject(self, ctx:dAngrParser.IDObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#IDObject.
    def exitIDObject(self, ctx:dAngrParser.IDObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#PropertyObject.
    def enterPropertyObject(self, ctx:dAngrParser.PropertyObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#PropertyObject.
    def exitPropertyObject(self, ctx:dAngrParser.PropertyObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#BoolObject.
    def enterBoolObject(self, ctx:dAngrParser.BoolObjectContext):
        pass

    # Exit a parse tree produced by dAngrParser#BoolObject.
    def exitBoolObject(self, ctx:dAngrParser.BoolObjectContext):
        pass


    # Enter a parse tree produced by dAngrParser#anything.
    def enterAnything(self, ctx:dAngrParser.AnythingContext):
        pass

    # Exit a parse tree produced by dAngrParser#anything.
    def exitAnything(self, ctx:dAngrParser.AnythingContext):
        pass


    # Enter a parse tree produced by dAngrParser#anything_no.
    def enterAnything_no(self, ctx:dAngrParser.Anything_noContext):
        pass

    # Exit a parse tree produced by dAngrParser#anything_no.
    def exitAnything_no(self, ctx:dAngrParser.Anything_noContext):
        pass


    # Enter a parse tree produced by dAngrParser#special_words.
    def enterSpecial_words(self, ctx:dAngrParser.Special_wordsContext):
        pass

    # Exit a parse tree produced by dAngrParser#special_words.
    def exitSpecial_words(self, ctx:dAngrParser.Special_wordsContext):
        pass


    # Enter a parse tree produced by dAngrParser#range.
    def enterRange(self, ctx:dAngrParser.RangeContext):
        pass

    # Exit a parse tree produced by dAngrParser#range.
    def exitRange(self, ctx:dAngrParser.RangeContext):
        pass


    # Enter a parse tree produced by dAngrParser#dangr_range.
    def enterDangr_range(self, ctx:dAngrParser.Dangr_rangeContext):
        pass

    # Exit a parse tree produced by dAngrParser#dangr_range.
    def exitDangr_range(self, ctx:dAngrParser.Dangr_rangeContext):
        pass


    # Enter a parse tree produced by dAngrParser#bash_range.
    def enterBash_range(self, ctx:dAngrParser.Bash_rangeContext):
        pass

    # Exit a parse tree produced by dAngrParser#bash_range.
    def exitBash_range(self, ctx:dAngrParser.Bash_rangeContext):
        pass


    # Enter a parse tree produced by dAngrParser#python_range.
    def enterPython_range(self, ctx:dAngrParser.Python_rangeContext):
        pass

    # Exit a parse tree produced by dAngrParser#python_range.
    def exitPython_range(self, ctx:dAngrParser.Python_rangeContext):
        pass


    # Enter a parse tree produced by dAngrParser#symbol.
    def enterSymbol(self, ctx:dAngrParser.SymbolContext):
        pass

    # Exit a parse tree produced by dAngrParser#symbol.
    def exitSymbol(self, ctx:dAngrParser.SymbolContext):
        pass



del dAngrParser