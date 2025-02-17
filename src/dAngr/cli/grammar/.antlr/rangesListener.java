// Generated from /workspaces/dAngr/src/dAngr/cli/grammar/ranges.g4 by ANTLR 4.13.1
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link rangesParser}.
 */
public interface rangesListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by {@link rangesParser#expression}.
	 * @param ctx the parse tree
	 */
	void enterExpression(rangesParser.ExpressionContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#expression}.
	 * @param ctx the parse tree
	 */
	void exitExpression(rangesParser.ExpressionContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#range}.
	 * @param ctx the parse tree
	 */
	void enterRange(rangesParser.RangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#range}.
	 * @param ctx the parse tree
	 */
	void exitRange(rangesParser.RangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#dangr_range}.
	 * @param ctx the parse tree
	 */
	void enterDangr_range(rangesParser.Dangr_rangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#dangr_range}.
	 * @param ctx the parse tree
	 */
	void exitDangr_range(rangesParser.Dangr_rangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#bash_range}.
	 * @param ctx the parse tree
	 */
	void enterBash_range(rangesParser.Bash_rangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#bash_range}.
	 * @param ctx the parse tree
	 */
	void exitBash_range(rangesParser.Bash_rangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#python_range}.
	 * @param ctx the parse tree
	 */
	void enterPython_range(rangesParser.Python_rangeContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#python_range}.
	 * @param ctx the parse tree
	 */
	void exitPython_range(rangesParser.Python_rangeContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#bash_content}.
	 * @param ctx the parse tree
	 */
	void enterBash_content(rangesParser.Bash_contentContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#bash_content}.
	 * @param ctx the parse tree
	 */
	void exitBash_content(rangesParser.Bash_contentContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#py_content}.
	 * @param ctx the parse tree
	 */
	void enterPy_content(rangesParser.Py_contentContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#py_content}.
	 * @param ctx the parse tree
	 */
	void exitPy_content(rangesParser.Py_contentContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#anything}.
	 * @param ctx the parse tree
	 */
	void enterAnything(rangesParser.AnythingContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#anything}.
	 * @param ctx the parse tree
	 */
	void exitAnything(rangesParser.AnythingContext ctx);
	/**
	 * Enter a parse tree produced by {@link rangesParser#symbol}.
	 * @param ctx the parse tree
	 */
	void enterSymbol(rangesParser.SymbolContext ctx);
	/**
	 * Exit a parse tree produced by {@link rangesParser#symbol}.
	 * @param ctx the parse tree
	 */
	void exitSymbol(rangesParser.SymbolContext ctx);
}