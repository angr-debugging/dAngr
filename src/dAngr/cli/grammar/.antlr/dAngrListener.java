// Generated from /workspaces/dAngr/src/dAngr/cli/grammar/dAngr.g4 by ANTLR 4.13.1
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link dAngrParser}.
 */
public interface dAngrListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by {@link dAngrParser#script}.
	 * @param ctx the parse tree
	 */
	void enterScript(dAngrParser.ScriptContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#script}.
	 * @param ctx the parse tree
	 */
	void exitScript(dAngrParser.ScriptContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#statement}.
	 * @param ctx the parse tree
	 */
	void enterStatement(dAngrParser.StatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#statement}.
	 * @param ctx the parse tree
	 */
	void exitStatement(dAngrParser.StatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#expression}.
	 * @param ctx the parse tree
	 */
	void enterExpression(dAngrParser.ExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#expression}.
	 * @param ctx the parse tree
	 */
	void exitExpression(dAngrParser.ExpressionContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionRange}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionRange(dAngrParser.ExpressionRangeContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionRange}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionRange(dAngrParser.ExpressionRangeContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionIn}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionIn(dAngrParser.ExpressionInContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionIn}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionIn(dAngrParser.ExpressionInContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionNot}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionNot(dAngrParser.ExpressionNotContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionNot}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionNot(dAngrParser.ExpressionNotContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionObject}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionObject(dAngrParser.ExpressionObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionObject}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionObject(dAngrParser.ExpressionObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionBool}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionBool(dAngrParser.ExpressionBoolContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionBool}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionBool(dAngrParser.ExpressionBoolContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionReference}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionReference(dAngrParser.ExpressionReferenceContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionReference}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionReference(dAngrParser.ExpressionReferenceContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionIf}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionIf(dAngrParser.ExpressionIfContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionIf}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionIf(dAngrParser.ExpressionIfContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionAlt}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionAlt(dAngrParser.ExpressionAltContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionAlt}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionAlt(dAngrParser.ExpressionAltContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionParenthesis}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionParenthesis(dAngrParser.ExpressionParenthesisContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionParenthesis}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionParenthesis(dAngrParser.ExpressionParenthesisContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ExpressionOperation}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void enterExpressionOperation(dAngrParser.ExpressionOperationContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ExpressionOperation}
	 * labeled alternative in {@link dAngrParser#expression_part}.
	 * @param ctx the parse tree
	 */
	void exitExpressionOperation(dAngrParser.ExpressionOperationContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#assignment}.
	 * @param ctx the parse tree
	 */
	void enterAssignment(dAngrParser.AssignmentContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#assignment}.
	 * @param ctx the parse tree
	 */
	void exitAssignment(dAngrParser.AssignmentContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#static_var}.
	 * @param ctx the parse tree
	 */
	void enterStatic_var(dAngrParser.Static_varContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#static_var}.
	 * @param ctx the parse tree
	 */
	void exitStatic_var(dAngrParser.Static_varContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#ext_command}.
	 * @param ctx the parse tree
	 */
	void enterExt_command(dAngrParser.Ext_commandContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#ext_command}.
	 * @param ctx the parse tree
	 */
	void exitExt_command(dAngrParser.Ext_commandContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#control_flow}.
	 * @param ctx the parse tree
	 */
	void enterControl_flow(dAngrParser.Control_flowContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#control_flow}.
	 * @param ctx the parse tree
	 */
	void exitControl_flow(dAngrParser.Control_flowContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#else_}.
	 * @param ctx the parse tree
	 */
	void enterElse_(dAngrParser.Else_Context ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#else_}.
	 * @param ctx the parse tree
	 */
	void exitElse_(dAngrParser.Else_Context ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#function_def}.
	 * @param ctx the parse tree
	 */
	void enterFunction_def(dAngrParser.Function_defContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#function_def}.
	 * @param ctx the parse tree
	 */
	void exitFunction_def(dAngrParser.Function_defContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#body}.
	 * @param ctx the parse tree
	 */
	void enterBody(dAngrParser.BodyContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#body}.
	 * @param ctx the parse tree
	 */
	void exitBody(dAngrParser.BodyContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#fstatement}.
	 * @param ctx the parse tree
	 */
	void enterFstatement(dAngrParser.FstatementContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#fstatement}.
	 * @param ctx the parse tree
	 */
	void exitFstatement(dAngrParser.FstatementContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#iterable}.
	 * @param ctx the parse tree
	 */
	void enterIterable(dAngrParser.IterableContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#iterable}.
	 * @param ctx the parse tree
	 */
	void exitIterable(dAngrParser.IterableContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#parameters}.
	 * @param ctx the parse tree
	 */
	void enterParameters(dAngrParser.ParametersContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#parameters}.
	 * @param ctx the parse tree
	 */
	void exitParameters(dAngrParser.ParametersContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#condition}.
	 * @param ctx the parse tree
	 */
	void enterCondition(dAngrParser.ConditionContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#condition}.
	 * @param ctx the parse tree
	 */
	void exitCondition(dAngrParser.ConditionContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#operation}.
	 * @param ctx the parse tree
	 */
	void enterOperation(dAngrParser.OperationContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#operation}.
	 * @param ctx the parse tree
	 */
	void exitOperation(dAngrParser.OperationContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#py_basic_content}.
	 * @param ctx the parse tree
	 */
	void enterPy_basic_content(dAngrParser.Py_basic_contentContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#py_basic_content}.
	 * @param ctx the parse tree
	 */
	void exitPy_basic_content(dAngrParser.Py_basic_contentContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#py_content}.
	 * @param ctx the parse tree
	 */
	void enterPy_content(dAngrParser.Py_contentContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#py_content}.
	 * @param ctx the parse tree
	 */
	void exitPy_content(dAngrParser.Py_contentContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#bash_content}.
	 * @param ctx the parse tree
	 */
	void enterBash_content(dAngrParser.Bash_contentContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#bash_content}.
	 * @param ctx the parse tree
	 */
	void exitBash_content(dAngrParser.Bash_contentContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#reference}.
	 * @param ctx the parse tree
	 */
	void enterReference(dAngrParser.ReferenceContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#reference}.
	 * @param ctx the parse tree
	 */
	void exitReference(dAngrParser.ReferenceContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#index}.
	 * @param ctx the parse tree
	 */
	void enterIndex(dAngrParser.IndexContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#index}.
	 * @param ctx the parse tree
	 */
	void exitIndex(dAngrParser.IndexContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#identifier}.
	 * @param ctx the parse tree
	 */
	void enterIdentifier(dAngrParser.IdentifierContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#identifier}.
	 * @param ctx the parse tree
	 */
	void exitIdentifier(dAngrParser.IdentifierContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#numeric}.
	 * @param ctx the parse tree
	 */
	void enterNumeric(dAngrParser.NumericContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#numeric}.
	 * @param ctx the parse tree
	 */
	void exitNumeric(dAngrParser.NumericContext ctx);
	/**
	 * Enter a parse tree produced by the {@code SlideStartLengthObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterSlideStartLengthObject(dAngrParser.SlideStartLengthObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code SlideStartLengthObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitSlideStartLengthObject(dAngrParser.SlideStartLengthObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ReferenceObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterReferenceObject(dAngrParser.ReferenceObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ReferenceObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitReferenceObject(dAngrParser.ReferenceObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code BinaryStringObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterBinaryStringObject(dAngrParser.BinaryStringObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code BinaryStringObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitBinaryStringObject(dAngrParser.BinaryStringObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code ListObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterListObject(dAngrParser.ListObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code ListObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitListObject(dAngrParser.ListObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code IndexedPropertyObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterIndexedPropertyObject(dAngrParser.IndexedPropertyObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code IndexedPropertyObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitIndexedPropertyObject(dAngrParser.IndexedPropertyObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code DictionaryObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterDictionaryObject(dAngrParser.DictionaryObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code DictionaryObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitDictionaryObject(dAngrParser.DictionaryObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code NumericObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterNumericObject(dAngrParser.NumericObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code NumericObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitNumericObject(dAngrParser.NumericObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code SliceStartEndObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterSliceStartEndObject(dAngrParser.SliceStartEndObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code SliceStartEndObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitSliceStartEndObject(dAngrParser.SliceStartEndObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code StringObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterStringObject(dAngrParser.StringObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code StringObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitStringObject(dAngrParser.StringObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code IDObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterIDObject(dAngrParser.IDObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code IDObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitIDObject(dAngrParser.IDObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code PropertyObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterPropertyObject(dAngrParser.PropertyObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code PropertyObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitPropertyObject(dAngrParser.PropertyObjectContext ctx);
	/**
	 * Enter a parse tree produced by the {@code BoolObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void enterBoolObject(dAngrParser.BoolObjectContext ctx);
	/**
	 * Exit a parse tree produced by the {@code BoolObject}
	 * labeled alternative in {@link dAngrParser#object}.
	 * @param ctx the parse tree
	 */
	void exitBoolObject(dAngrParser.BoolObjectContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#anything}.
	 * @param ctx the parse tree
	 */
	void enterAnything(dAngrParser.AnythingContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#anything}.
	 * @param ctx the parse tree
	 */
	void exitAnything(dAngrParser.AnythingContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#anything_no}.
	 * @param ctx the parse tree
	 */
	void enterAnything_no(dAngrParser.Anything_noContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#anything_no}.
	 * @param ctx the parse tree
	 */
	void exitAnything_no(dAngrParser.Anything_noContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#special_words}.
	 * @param ctx the parse tree
	 */
	void enterSpecial_words(dAngrParser.Special_wordsContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#special_words}.
	 * @param ctx the parse tree
	 */
	void exitSpecial_words(dAngrParser.Special_wordsContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#range}.
	 * @param ctx the parse tree
	 */
	void enterRange(dAngrParser.RangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#range}.
	 * @param ctx the parse tree
	 */
	void exitRange(dAngrParser.RangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#dangr_range}.
	 * @param ctx the parse tree
	 */
	void enterDangr_range(dAngrParser.Dangr_rangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#dangr_range}.
	 * @param ctx the parse tree
	 */
	void exitDangr_range(dAngrParser.Dangr_rangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#bash_range}.
	 * @param ctx the parse tree
	 */
	void enterBash_range(dAngrParser.Bash_rangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#bash_range}.
	 * @param ctx the parse tree
	 */
	void exitBash_range(dAngrParser.Bash_rangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#python_range}.
	 * @param ctx the parse tree
	 */
	void enterPython_range(dAngrParser.Python_rangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#python_range}.
	 * @param ctx the parse tree
	 */
	void exitPython_range(dAngrParser.Python_rangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link dAngrParser#symbol}.
	 * @param ctx the parse tree
	 */
	void enterSymbol(dAngrParser.SymbolContext ctx);
	/**
	 * Exit a parse tree produced by {@link dAngrParser#symbol}.
	 * @param ctx the parse tree
	 */
	void exitSymbol(dAngrParser.SymbolContext ctx);
}