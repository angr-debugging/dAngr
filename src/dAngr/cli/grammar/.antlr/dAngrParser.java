// Generated from /workspaces/dAngr/src/dAngr/cli/grammar/dAngr.g4 by ANTLR 4.13.1

import re as rex

import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue"})
public class dAngrParser extends Parser {
	static { RuntimeMetaData.checkVersion("4.13.1", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		STATIC=1, CIF=2, CTHEN=3, CELSE=4, RANGE=5, DEF=6, IF=7, ELSE=8, FOR=9, 
		IN=10, WHILE=11, BOOL=12, HELP=13, RETURN=14, BREAK=15, CONTINUE=16, NEWLINE=17, 
		WS=18, HEX_NUMBERS=19, NUMBERS=20, NUMBER=21, LETTERS=22, LETTER=23, SYM_DB=24, 
		REG_DB=25, VARS_DB=26, MEM_DB=27, STATE=28, STRING=29, BINARY_STRING=30, 
		ESCAPED_QUOTE=31, ESCAPED_SINGLE_QUOTE=32, SESC_SEQ=33, ESC_SEQ=34, ARROW=35, 
		LPAREN=36, RPAREN=37, BANG=38, AMP=39, DOLLAR=40, COLON=41, SCOLON=42, 
		COMMA=43, QUOTE=44, SQUOTE=45, AT=46, DOT=47, BAR=48, BRA=49, KET=50, 
		BRACE=51, KETCE=52, HAT=53, HASH=54, PERC=55, MUL=56, ADD=57, DIV=58, 
		FLOORDIV=59, LSHIFT=60, RSHIFT=61, POW=62, ASSIGN=63, EQ=64, NEQ=65, LT=66, 
		GT=67, LE=68, GE=69, AND=70, OR=71, QMARK=72, TILDE=73, TICK=74, UNDERSCORE=75, 
		DASH=76, INDENT=77, DEDENT=78;
	public static final int
		RULE_script = 0, RULE_statement = 1, RULE_expression = 2, RULE_expression_part = 3, 
		RULE_assignment = 4, RULE_static_var = 5, RULE_ext_command = 6, RULE_control_flow = 7, 
		RULE_else_ = 8, RULE_function_def = 9, RULE_body = 10, RULE_fstatement = 11, 
		RULE_iterable = 12, RULE_parameters = 13, RULE_condition = 14, RULE_operation = 15, 
		RULE_py_basic_content = 16, RULE_py_content = 17, RULE_bash_content = 18, 
		RULE_reference = 19, RULE_index = 20, RULE_identifier = 21, RULE_numeric = 22, 
		RULE_object = 23, RULE_anything = 24, RULE_special_words = 25, RULE_range = 26, 
		RULE_dangr_range = 27, RULE_bash_range = 28, RULE_python_range = 29, RULE_symbol = 30;
	private static String[] makeRuleNames() {
		return new String[] {
			"script", "statement", "expression", "expression_part", "assignment", 
			"static_var", "ext_command", "control_flow", "else_", "function_def", 
			"body", "fstatement", "iterable", "parameters", "condition", "operation", 
			"py_basic_content", "py_content", "bash_content", "reference", "index", 
			"identifier", "numeric", "object", "anything", "special_words", "range", 
			"dangr_range", "bash_range", "python_range", "symbol"
		};
	}
	public static final String[] ruleNames = makeRuleNames();

	private static String[] makeLiteralNames() {
		return new String[] {
			null, "'static'", "'IIF'", "'THEN'", "'ELSE'", "'range'", "'def'", "'if'", 
			"'else'", "'for'", "'in'", "'while'", null, "'help'", "'return'", "'break'", 
			"'continue'", null, null, null, null, null, null, null, "'&sym'", "'&reg'", 
			"'&vars'", "'&mem'", "'&state'", null, null, null, null, null, null, 
			"'->'", "'('", "')'", "'!'", "'&'", "'$'", "':'", "';'", "','", "'\"'", 
			"'''", "'@'", "'.'", "'|'", "'['", "']'", "'{'", "'}'", "'^'", "'#'", 
			"'%'", "'*'", "'+'", "'/'", "'//'", "'<<'", "'>>'", "'**'", "'='", "'=='", 
			"'!='", "'<'", "'>'", "'<='", "'>='", "'&&'", "'||'", "'?'", "'~'", "'`'", 
			"'_'", "'-'"
		};
	}
	private static final String[] _LITERAL_NAMES = makeLiteralNames();
	private static String[] makeSymbolicNames() {
		return new String[] {
			null, "STATIC", "CIF", "CTHEN", "CELSE", "RANGE", "DEF", "IF", "ELSE", 
			"FOR", "IN", "WHILE", "BOOL", "HELP", "RETURN", "BREAK", "CONTINUE", 
			"NEWLINE", "WS", "HEX_NUMBERS", "NUMBERS", "NUMBER", "LETTERS", "LETTER", 
			"SYM_DB", "REG_DB", "VARS_DB", "MEM_DB", "STATE", "STRING", "BINARY_STRING", 
			"ESCAPED_QUOTE", "ESCAPED_SINGLE_QUOTE", "SESC_SEQ", "ESC_SEQ", "ARROW", 
			"LPAREN", "RPAREN", "BANG", "AMP", "DOLLAR", "COLON", "SCOLON", "COMMA", 
			"QUOTE", "SQUOTE", "AT", "DOT", "BAR", "BRA", "KET", "BRACE", "KETCE", 
			"HAT", "HASH", "PERC", "MUL", "ADD", "DIV", "FLOORDIV", "LSHIFT", "RSHIFT", 
			"POW", "ASSIGN", "EQ", "NEQ", "LT", "GT", "LE", "GE", "AND", "OR", "QMARK", 
			"TILDE", "TICK", "UNDERSCORE", "DASH", "INDENT", "DEDENT"
		};
	}
	private static final String[] _SYMBOLIC_NAMES = makeSymbolicNames();
	public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

	/**
	 * @deprecated Use {@link #VOCABULARY} instead.
	 */
	@Deprecated
	public static final String[] tokenNames;
	static {
		tokenNames = new String[_SYMBOLIC_NAMES.length];
		for (int i = 0; i < tokenNames.length; i++) {
			tokenNames[i] = VOCABULARY.getLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = VOCABULARY.getSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}
	}

	@Override
	@Deprecated
	public String[] getTokenNames() {
		return tokenNames;
	}

	@Override

	public Vocabulary getVocabulary() {
		return VOCABULARY;
	}

	@Override
	public String getGrammarFileName() { return "dAngr.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public dAngrParser(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ScriptContext extends ParserRuleContext {
		public TerminalNode EOF() { return getToken(dAngrParser.EOF, 0); }
		public List<TerminalNode> NEWLINE() { return getTokens(dAngrParser.NEWLINE); }
		public TerminalNode NEWLINE(int i) {
			return getToken(dAngrParser.NEWLINE, i);
		}
		public TerminalNode QMARK() { return getToken(dAngrParser.QMARK, 0); }
		public TerminalNode HELP() { return getToken(dAngrParser.HELP, 0); }
		public TerminalNode WS() { return getToken(dAngrParser.WS, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public List<StatementContext> statement() {
			return getRuleContexts(StatementContext.class);
		}
		public StatementContext statement(int i) {
			return getRuleContext(StatementContext.class,i);
		}
		public List<Function_defContext> function_def() {
			return getRuleContexts(Function_defContext.class);
		}
		public Function_defContext function_def(int i) {
			return getRuleContext(Function_defContext.class,i);
		}
		public ScriptContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_script; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterScript(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitScript(this);
		}
	}

	public final ScriptContext script() throws RecognitionException {
		ScriptContext _localctx = new ScriptContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_script);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(76);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,3,_ctx) ) {
			case 1:
				{
				setState(62);
				_la = _input.LA(1);
				if ( !(_la==HELP || _la==QMARK) ) {
				_errHandler.recoverInline(this);
				}
				else {
					if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
					_errHandler.reportMatch(this);
					consume();
				}
				setState(65);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(63);
					match(WS);
					setState(64);
					identifier();
					}
				}

				setState(67);
				match(NEWLINE);
				}
				break;
			case 2:
				{
				setState(73);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while ((((_la) & ~0x3f) == 0 && ((1L << _la) & 2816744768667646L) != 0) || _la==UNDERSCORE || _la==DASH) {
					{
					setState(71);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,1,_ctx) ) {
					case 1:
						{
						setState(68);
						match(NEWLINE);
						}
						break;
					case 2:
						{
						setState(69);
						statement();
						}
						break;
					case 3:
						{
						setState(70);
						function_def();
						}
						break;
					}
					}
					setState(75);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				}
				break;
			}
			setState(78);
			match(EOF);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class StatementContext extends ParserRuleContext {
		public Control_flowContext control_flow() {
			return getRuleContext(Control_flowContext.class,0);
		}
		public AssignmentContext assignment() {
			return getRuleContext(AssignmentContext.class,0);
		}
		public TerminalNode NEWLINE() { return getToken(dAngrParser.NEWLINE, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public Static_varContext static_var() {
			return getRuleContext(Static_varContext.class,0);
		}
		public Ext_commandContext ext_command() {
			return getRuleContext(Ext_commandContext.class,0);
		}
		public StatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_statement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterStatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitStatement(this);
		}
	}

	public final StatementContext statement() throws RecognitionException {
		StatementContext _localctx = new StatementContext(_ctx, getState());
		enterRule(_localctx, 2, RULE_statement);
		try {
			setState(93);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,4,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(80);
				control_flow();
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(81);
				assignment();
				setState(82);
				match(NEWLINE);
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				setState(84);
				expression();
				setState(85);
				match(NEWLINE);
				}
				break;
			case 4:
				enterOuterAlt(_localctx, 4);
				{
				setState(87);
				static_var();
				setState(88);
				match(NEWLINE);
				}
				break;
			case 5:
				enterOuterAlt(_localctx, 5);
				{
				setState(90);
				ext_command();
				setState(91);
				match(NEWLINE);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionContext extends ParserRuleContext {
		public List<IdentifierContext> identifier() {
			return getRuleContexts(IdentifierContext.class);
		}
		public IdentifierContext identifier(int i) {
			return getRuleContext(IdentifierContext.class,i);
		}
		public TerminalNode DOT() { return getToken(dAngrParser.DOT, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public List<Expression_partContext> expression_part() {
			return getRuleContexts(Expression_partContext.class);
		}
		public Expression_partContext expression_part(int i) {
			return getRuleContext(Expression_partContext.class,i);
		}
		public List<TerminalNode> ASSIGN() { return getTokens(dAngrParser.ASSIGN); }
		public TerminalNode ASSIGN(int i) {
			return getToken(dAngrParser.ASSIGN, i);
		}
		public ExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_expression; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpression(this);
		}
	}

	public final ExpressionContext expression() throws RecognitionException {
		ExpressionContext _localctx = new ExpressionContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_expression);
		try {
			int _alt;
			setState(114);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,8,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(98);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,5,_ctx) ) {
				case 1:
					{
					setState(95);
					identifier();
					setState(96);
					match(DOT);
					}
					break;
				}
				setState(100);
				identifier();
				setState(110);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,7,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(101);
						match(WS);
						setState(105);
						_errHandler.sync(this);
						switch ( getInterpreter().adaptivePredict(_input,6,_ctx) ) {
						case 1:
							{
							setState(102);
							identifier();
							setState(103);
							match(ASSIGN);
							}
							break;
						}
						setState(107);
						expression_part(0);
						}
						} 
					}
					setState(112);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,7,_ctx);
				}
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(113);
				expression_part(0);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Expression_partContext extends ParserRuleContext {
		public Expression_partContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_expression_part; }
	 
		public Expression_partContext() { }
		public void copyFrom(Expression_partContext ctx) {
			super.copyFrom(ctx);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionRangeContext extends Expression_partContext {
		public TerminalNode RANGE() { return getToken(dAngrParser.RANGE, 0); }
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public List<Expression_partContext> expression_part() {
			return getRuleContexts(Expression_partContext.class);
		}
		public Expression_partContext expression_part(int i) {
			return getRuleContext(Expression_partContext.class,i);
		}
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public List<TerminalNode> COMMA() { return getTokens(dAngrParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(dAngrParser.COMMA, i);
		}
		public ExpressionRangeContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionRange(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionRange(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionInContext extends Expression_partContext {
		public List<Expression_partContext> expression_part() {
			return getRuleContexts(Expression_partContext.class);
		}
		public Expression_partContext expression_part(int i) {
			return getRuleContext(Expression_partContext.class,i);
		}
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public TerminalNode IN() { return getToken(dAngrParser.IN, 0); }
		public ExpressionInContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionIn(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionIn(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionObjectContext extends Expression_partContext {
		public ObjectContext object() {
			return getRuleContext(ObjectContext.class,0);
		}
		public ExpressionObjectContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionBoolContext extends Expression_partContext {
		public TerminalNode BOOL() { return getToken(dAngrParser.BOOL, 0); }
		public ExpressionBoolContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionBool(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionBool(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionReferenceContext extends Expression_partContext {
		public ReferenceContext reference() {
			return getRuleContext(ReferenceContext.class,0);
		}
		public ExpressionReferenceContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionReference(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionReference(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionIfContext extends Expression_partContext {
		public TerminalNode CIF() { return getToken(dAngrParser.CIF, 0); }
		public ConditionContext condition() {
			return getRuleContext(ConditionContext.class,0);
		}
		public TerminalNode CTHEN() { return getToken(dAngrParser.CTHEN, 0); }
		public List<Expression_partContext> expression_part() {
			return getRuleContexts(Expression_partContext.class);
		}
		public Expression_partContext expression_part(int i) {
			return getRuleContext(Expression_partContext.class,i);
		}
		public TerminalNode CELSE() { return getToken(dAngrParser.CELSE, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public ExpressionIfContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionIf(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionIf(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionAltContext extends Expression_partContext {
		public RangeContext range() {
			return getRuleContext(RangeContext.class,0);
		}
		public ExpressionAltContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionAlt(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionAlt(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionParenthesisContext extends Expression_partContext {
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public ExpressionParenthesisContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionParenthesis(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionParenthesis(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionOperationContext extends Expression_partContext {
		public ObjectContext object() {
			return getRuleContext(ObjectContext.class,0);
		}
		public OperationContext operation() {
			return getRuleContext(OperationContext.class,0);
		}
		public Expression_partContext expression_part() {
			return getRuleContext(Expression_partContext.class,0);
		}
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public ExpressionOperationContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionOperation(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionOperation(this);
		}
	}

	public final Expression_partContext expression_part() throws RecognitionException {
		return expression_part(0);
	}

	private Expression_partContext expression_part(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		Expression_partContext _localctx = new Expression_partContext(_ctx, _parentState);
		Expression_partContext _prevctx = _localctx;
		int _startState = 6;
		enterRecursionRule(_localctx, 6, RULE_expression_part, _p);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(194);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,26,_ctx) ) {
			case 1:
				{
				_localctx = new ExpressionIfContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(117);
				match(CIF);
				setState(119);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(118);
					match(WS);
					}
				}

				setState(121);
				condition();
				setState(123);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(122);
					match(WS);
					}
				}

				setState(125);
				match(CTHEN);
				setState(127);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(126);
					match(WS);
					}
				}

				setState(129);
				expression_part(0);
				setState(131);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(130);
					match(WS);
					}
				}

				setState(133);
				match(CELSE);
				setState(135);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(134);
					match(WS);
					}
				}

				setState(137);
				expression_part(9);
				}
				break;
			case 2:
				{
				_localctx = new ExpressionParenthesisContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(139);
				match(LPAREN);
				setState(141);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(140);
					match(WS);
					}
				}

				setState(143);
				expression();
				setState(145);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(144);
					match(WS);
					}
				}

				setState(147);
				match(RPAREN);
				}
				break;
			case 3:
				{
				_localctx = new ExpressionRangeContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(149);
				match(RANGE);
				setState(150);
				match(LPAREN);
				setState(152);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(151);
					match(WS);
					}
				}

				setState(154);
				expression_part(0);
				setState(156);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(155);
					match(WS);
					}
				}

				setState(176);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==COMMA) {
					{
					setState(158);
					match(COMMA);
					setState(160);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(159);
						match(WS);
						}
					}

					setState(162);
					expression_part(0);
					setState(164);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(163);
						match(WS);
						}
					}

					setState(174);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==COMMA) {
						{
						setState(166);
						match(COMMA);
						setState(168);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(167);
							match(WS);
							}
						}

						setState(170);
						expression_part(0);
						setState(172);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(171);
							match(WS);
							}
						}

						}
					}

					}
				}

				setState(178);
				match(RPAREN);
				}
				break;
			case 4:
				{
				_localctx = new ExpressionAltContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(180);
				range();
				}
				break;
			case 5:
				{
				_localctx = new ExpressionReferenceContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(181);
				reference();
				}
				break;
			case 6:
				{
				_localctx = new ExpressionBoolContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(182);
				match(BOOL);
				}
				break;
			case 7:
				{
				_localctx = new ExpressionOperationContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(183);
				object(0);
				{
				setState(185);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(184);
					match(WS);
					}
				}

				setState(187);
				operation();
				setState(189);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(188);
					match(WS);
					}
				}

				setState(191);
				expression_part(0);
				}
				}
				break;
			case 8:
				{
				_localctx = new ExpressionObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(193);
				object(0);
				}
				break;
			}
			_ctx.stop = _input.LT(-1);
			setState(203);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,27,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					{
					_localctx = new ExpressionInContext(new Expression_partContext(_parentctx, _parentState));
					pushNewRecursionContext(_localctx, _startState, RULE_expression_part);
					setState(196);
					if (!(precpred(_ctx, 6))) throw new FailedPredicateException(this, "precpred(_ctx, 6)");
					setState(197);
					match(WS);
					setState(198);
					match(IN);
					setState(199);
					match(WS);
					setState(200);
					expression_part(7);
					}
					} 
				}
				setState(205);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,27,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class AssignmentContext extends ParserRuleContext {
		public TerminalNode ASSIGN() { return getToken(dAngrParser.ASSIGN, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public Static_varContext static_var() {
			return getRuleContext(Static_varContext.class,0);
		}
		public ObjectContext object() {
			return getRuleContext(ObjectContext.class,0);
		}
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public AssignmentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_assignment; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterAssignment(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitAssignment(this);
		}
	}

	public final AssignmentContext assignment() throws RecognitionException {
		AssignmentContext _localctx = new AssignmentContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_assignment);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(208);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,28,_ctx) ) {
			case 1:
				{
				setState(206);
				static_var();
				}
				break;
			case 2:
				{
				setState(207);
				object(0);
				}
				break;
			}
			setState(211);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(210);
				match(WS);
				}
			}

			setState(213);
			match(ASSIGN);
			setState(215);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(214);
				match(WS);
				}
			}

			setState(217);
			expression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Static_varContext extends ParserRuleContext {
		public TerminalNode STATIC() { return getToken(dAngrParser.STATIC, 0); }
		public TerminalNode WS() { return getToken(dAngrParser.WS, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public Static_varContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_static_var; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterStatic_var(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitStatic_var(this);
		}
	}

	public final Static_varContext static_var() throws RecognitionException {
		Static_varContext _localctx = new Static_varContext(_ctx, getState());
		enterRule(_localctx, 10, RULE_static_var);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(219);
			match(STATIC);
			setState(220);
			match(WS);
			setState(221);
			identifier();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Ext_commandContext extends ParserRuleContext {
		public TerminalNode BANG() { return getToken(dAngrParser.BANG, 0); }
		public Py_basic_contentContext py_basic_content() {
			return getRuleContext(Py_basic_contentContext.class,0);
		}
		public TerminalNode AMP() { return getToken(dAngrParser.AMP, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public TerminalNode DOLLAR() { return getToken(dAngrParser.DOLLAR, 0); }
		public Bash_contentContext bash_content() {
			return getRuleContext(Bash_contentContext.class,0);
		}
		public Ext_commandContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_ext_command; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExt_command(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExt_command(this);
		}
	}

	public final Ext_commandContext ext_command() throws RecognitionException {
		Ext_commandContext _localctx = new Ext_commandContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_ext_command);
		try {
			setState(229);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case BANG:
				enterOuterAlt(_localctx, 1);
				{
				setState(223);
				match(BANG);
				setState(224);
				py_basic_content();
				}
				break;
			case AMP:
				enterOuterAlt(_localctx, 2);
				{
				setState(225);
				match(AMP);
				setState(226);
				expression();
				}
				break;
			case DOLLAR:
				enterOuterAlt(_localctx, 3);
				{
				setState(227);
				match(DOLLAR);
				setState(228);
				bash_content();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Control_flowContext extends ParserRuleContext {
		public TerminalNode IF() { return getToken(dAngrParser.IF, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public ConditionContext condition() {
			return getRuleContext(ConditionContext.class,0);
		}
		public TerminalNode COLON() { return getToken(dAngrParser.COLON, 0); }
		public BodyContext body() {
			return getRuleContext(BodyContext.class,0);
		}
		public Else_Context else_() {
			return getRuleContext(Else_Context.class,0);
		}
		public TerminalNode FOR() { return getToken(dAngrParser.FOR, 0); }
		public List<IdentifierContext> identifier() {
			return getRuleContexts(IdentifierContext.class);
		}
		public IdentifierContext identifier(int i) {
			return getRuleContext(IdentifierContext.class,i);
		}
		public TerminalNode IN() { return getToken(dAngrParser.IN, 0); }
		public IterableContext iterable() {
			return getRuleContext(IterableContext.class,0);
		}
		public TerminalNode COMMA() { return getToken(dAngrParser.COMMA, 0); }
		public TerminalNode WHILE() { return getToken(dAngrParser.WHILE, 0); }
		public Control_flowContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_control_flow; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterControl_flow(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitControl_flow(this);
		}
	}

	public final Control_flowContext control_flow() throws RecognitionException {
		Control_flowContext _localctx = new Control_flowContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_control_flow);
		int _la;
		try {
			setState(274);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case IF:
				enterOuterAlt(_localctx, 1);
				{
				setState(231);
				match(IF);
				setState(232);
				match(WS);
				setState(233);
				condition();
				setState(235);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(234);
					match(WS);
					}
				}

				setState(237);
				match(COLON);
				setState(238);
				body();
				setState(240);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,33,_ctx) ) {
				case 1:
					{
					setState(239);
					else_();
					}
					break;
				}
				}
				break;
			case FOR:
				enterOuterAlt(_localctx, 2);
				{
				setState(242);
				match(FOR);
				setState(243);
				match(WS);
				setState(244);
				identifier();
				setState(253);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,36,_ctx) ) {
				case 1:
					{
					setState(246);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(245);
						match(WS);
						}
					}

					setState(248);
					match(COMMA);
					setState(250);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(249);
						match(WS);
						}
					}

					setState(252);
					identifier();
					}
					break;
				}
				setState(255);
				match(WS);
				setState(256);
				match(IN);
				setState(257);
				match(WS);
				setState(258);
				iterable();
				setState(260);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(259);
					match(WS);
					}
				}

				setState(262);
				match(COLON);
				setState(263);
				body();
				}
				break;
			case WHILE:
				enterOuterAlt(_localctx, 3);
				{
				setState(265);
				match(WHILE);
				setState(266);
				match(WS);
				setState(267);
				condition();
				setState(269);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(268);
					match(WS);
					}
				}

				setState(271);
				match(COLON);
				setState(272);
				body();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Else_Context extends ParserRuleContext {
		public TerminalNode ELSE() { return getToken(dAngrParser.ELSE, 0); }
		public TerminalNode COLON() { return getToken(dAngrParser.COLON, 0); }
		public BodyContext body() {
			return getRuleContext(BodyContext.class,0);
		}
		public TerminalNode WS() { return getToken(dAngrParser.WS, 0); }
		public Else_Context(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_else_; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterElse_(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitElse_(this);
		}
	}

	public final Else_Context else_() throws RecognitionException {
		Else_Context _localctx = new Else_Context(_ctx, getState());
		enterRule(_localctx, 16, RULE_else_);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(276);
			match(ELSE);
			setState(278);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(277);
				match(WS);
				}
			}

			setState(280);
			match(COLON);
			setState(281);
			body();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Function_defContext extends ParserRuleContext {
		public TerminalNode DEF() { return getToken(dAngrParser.DEF, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public TerminalNode COLON() { return getToken(dAngrParser.COLON, 0); }
		public BodyContext body() {
			return getRuleContext(BodyContext.class,0);
		}
		public ParametersContext parameters() {
			return getRuleContext(ParametersContext.class,0);
		}
		public Function_defContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_function_def; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterFunction_def(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitFunction_def(this);
		}
	}

	public final Function_defContext function_def() throws RecognitionException {
		Function_defContext _localctx = new Function_defContext(_ctx, getState());
		enterRule(_localctx, 18, RULE_function_def);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(283);
			match(DEF);
			setState(284);
			match(WS);
			setState(285);
			identifier();
			setState(287);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(286);
				match(WS);
				}
			}

			setState(289);
			match(LPAREN);
			setState(291);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 4325374L) != 0) || _la==UNDERSCORE) {
				{
				setState(290);
				parameters();
				}
			}

			setState(293);
			match(RPAREN);
			setState(295);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(294);
				match(WS);
				}
			}

			setState(297);
			match(COLON);
			setState(298);
			body();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class BodyContext extends ParserRuleContext {
		public TerminalNode INDENT() { return getToken(dAngrParser.INDENT, 0); }
		public TerminalNode DEDENT() { return getToken(dAngrParser.DEDENT, 0); }
		public List<FstatementContext> fstatement() {
			return getRuleContexts(FstatementContext.class);
		}
		public FstatementContext fstatement(int i) {
			return getRuleContext(FstatementContext.class,i);
		}
		public List<TerminalNode> NEWLINE() { return getTokens(dAngrParser.NEWLINE); }
		public TerminalNode NEWLINE(int i) {
			return getToken(dAngrParser.NEWLINE, i);
		}
		public BodyContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_body; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterBody(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitBody(this);
		}
	}

	public final BodyContext body() throws RecognitionException {
		BodyContext _localctx = new BodyContext(_ctx, getState());
		enterRule(_localctx, 20, RULE_body);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(300);
			match(INDENT);
			setState(305); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(301);
				fstatement();
				setState(303);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==NEWLINE) {
					{
					setState(302);
					match(NEWLINE);
					}
				}

				}
				}
				setState(307); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( (((_la) & ~0x3f) == 0 && ((1L << _la) & 2816744768536574L) != 0) || _la==UNDERSCORE || _la==DASH );
			setState(309);
			match(DEDENT);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class FstatementContext extends ParserRuleContext {
		public TerminalNode BREAK() { return getToken(dAngrParser.BREAK, 0); }
		public TerminalNode CONTINUE() { return getToken(dAngrParser.CONTINUE, 0); }
		public TerminalNode RETURN() { return getToken(dAngrParser.RETURN, 0); }
		public TerminalNode WS() { return getToken(dAngrParser.WS, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public StatementContext statement() {
			return getRuleContext(StatementContext.class,0);
		}
		public FstatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_fstatement; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterFstatement(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitFstatement(this);
		}
	}

	public final FstatementContext fstatement() throws RecognitionException {
		FstatementContext _localctx = new FstatementContext(_ctx, getState());
		enterRule(_localctx, 22, RULE_fstatement);
		try {
			setState(317);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,46,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(311);
				match(BREAK);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(312);
				match(CONTINUE);
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				{
				setState(313);
				match(RETURN);
				setState(314);
				match(WS);
				setState(315);
				expression();
				}
				}
				break;
			case 4:
				enterOuterAlt(_localctx, 4);
				{
				setState(316);
				statement();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class IterableContext extends ParserRuleContext {
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public IterableContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_iterable; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterIterable(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitIterable(this);
		}
	}

	public final IterableContext iterable() throws RecognitionException {
		IterableContext _localctx = new IterableContext(_ctx, getState());
		enterRule(_localctx, 24, RULE_iterable);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(319);
			expression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ParametersContext extends ParserRuleContext {
		public List<IdentifierContext> identifier() {
			return getRuleContexts(IdentifierContext.class);
		}
		public IdentifierContext identifier(int i) {
			return getRuleContext(IdentifierContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(dAngrParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(dAngrParser.COMMA, i);
		}
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public ParametersContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_parameters; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterParameters(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitParameters(this);
		}
	}

	public final ParametersContext parameters() throws RecognitionException {
		ParametersContext _localctx = new ParametersContext(_ctx, getState());
		enterRule(_localctx, 26, RULE_parameters);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(321);
			identifier();
			setState(332);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==WS || _la==COMMA) {
				{
				{
				setState(323);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(322);
					match(WS);
					}
				}

				setState(325);
				match(COMMA);
				setState(327);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(326);
					match(WS);
					}
				}

				setState(329);
				identifier();
				}
				}
				setState(334);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ConditionContext extends ParserRuleContext {
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public ConditionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_condition; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterCondition(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitCondition(this);
		}
	}

	public final ConditionContext condition() throws RecognitionException {
		ConditionContext _localctx = new ConditionContext(_ctx, getState());
		enterRule(_localctx, 28, RULE_condition);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(335);
			expression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class OperationContext extends ParserRuleContext {
		public TerminalNode ADD() { return getToken(dAngrParser.ADD, 0); }
		public TerminalNode DASH() { return getToken(dAngrParser.DASH, 0); }
		public TerminalNode MUL() { return getToken(dAngrParser.MUL, 0); }
		public TerminalNode DIV() { return getToken(dAngrParser.DIV, 0); }
		public TerminalNode PERC() { return getToken(dAngrParser.PERC, 0); }
		public TerminalNode POW() { return getToken(dAngrParser.POW, 0); }
		public TerminalNode EQ() { return getToken(dAngrParser.EQ, 0); }
		public TerminalNode NEQ() { return getToken(dAngrParser.NEQ, 0); }
		public TerminalNode GT() { return getToken(dAngrParser.GT, 0); }
		public TerminalNode LT() { return getToken(dAngrParser.LT, 0); }
		public TerminalNode LE() { return getToken(dAngrParser.LE, 0); }
		public TerminalNode GE() { return getToken(dAngrParser.GE, 0); }
		public TerminalNode AND() { return getToken(dAngrParser.AND, 0); }
		public TerminalNode OR() { return getToken(dAngrParser.OR, 0); }
		public TerminalNode FLOORDIV() { return getToken(dAngrParser.FLOORDIV, 0); }
		public TerminalNode LSHIFT() { return getToken(dAngrParser.LSHIFT, 0); }
		public TerminalNode RSHIFT() { return getToken(dAngrParser.RSHIFT, 0); }
		public TerminalNode AMP() { return getToken(dAngrParser.AMP, 0); }
		public TerminalNode BAR() { return getToken(dAngrParser.BAR, 0); }
		public OperationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_operation; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterOperation(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitOperation(this);
		}
	}

	public final OperationContext operation() throws RecognitionException {
		OperationContext _localctx = new OperationContext(_ctx, getState());
		enterRule(_localctx, 30, RULE_operation);
		try {
			setState(356);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case ADD:
				enterOuterAlt(_localctx, 1);
				{
				setState(337);
				match(ADD);
				}
				break;
			case DASH:
				enterOuterAlt(_localctx, 2);
				{
				setState(338);
				match(DASH);
				}
				break;
			case MUL:
				enterOuterAlt(_localctx, 3);
				{
				setState(339);
				match(MUL);
				}
				break;
			case DIV:
				enterOuterAlt(_localctx, 4);
				{
				setState(340);
				match(DIV);
				}
				break;
			case PERC:
				enterOuterAlt(_localctx, 5);
				{
				setState(341);
				match(PERC);
				}
				break;
			case POW:
				enterOuterAlt(_localctx, 6);
				{
				setState(342);
				match(POW);
				}
				break;
			case EQ:
				enterOuterAlt(_localctx, 7);
				{
				setState(343);
				match(EQ);
				}
				break;
			case NEQ:
				enterOuterAlt(_localctx, 8);
				{
				setState(344);
				match(NEQ);
				}
				break;
			case GT:
				enterOuterAlt(_localctx, 9);
				{
				setState(345);
				match(GT);
				}
				break;
			case LT:
				enterOuterAlt(_localctx, 10);
				{
				setState(346);
				match(LT);
				}
				break;
			case LE:
				enterOuterAlt(_localctx, 11);
				{
				setState(347);
				match(LE);
				}
				break;
			case GE:
				enterOuterAlt(_localctx, 12);
				{
				setState(348);
				match(GE);
				}
				break;
			case AND:
				enterOuterAlt(_localctx, 13);
				{
				setState(349);
				match(AND);
				}
				break;
			case OR:
				enterOuterAlt(_localctx, 14);
				{
				setState(350);
				match(OR);
				setState(351);
				match(FLOORDIV);
				}
				break;
			case LSHIFT:
				enterOuterAlt(_localctx, 15);
				{
				setState(352);
				match(LSHIFT);
				}
				break;
			case RSHIFT:
				enterOuterAlt(_localctx, 16);
				{
				setState(353);
				match(RSHIFT);
				}
				break;
			case AMP:
				enterOuterAlt(_localctx, 17);
				{
				setState(354);
				match(AMP);
				}
				break;
			case BAR:
				enterOuterAlt(_localctx, 18);
				{
				setState(355);
				match(BAR);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Py_basic_contentContext extends ParserRuleContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public List<Py_contentContext> py_content() {
			return getRuleContexts(Py_contentContext.class);
		}
		public Py_contentContext py_content(int i) {
			return getRuleContext(Py_contentContext.class,i);
		}
		public Py_basic_contentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_py_basic_content; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterPy_basic_content(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitPy_basic_content(this);
		}
	}

	public final Py_basic_contentContext py_basic_content() throws RecognitionException {
		Py_basic_contentContext _localctx = new Py_basic_contentContext(_ctx, getState());
		enterRule(_localctx, 32, RULE_py_basic_content);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(358);
			identifier();
			setState(360);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(359);
				match(WS);
				}
			}

			setState(362);
			match(LPAREN);
			setState(364);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,52,_ctx) ) {
			case 1:
				{
				setState(363);
				match(WS);
				}
				break;
			}
			setState(369);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while ((((_la) & ~0x3f) == 0 && ((1L << _la) & -204022087682L) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & 8191L) != 0)) {
				{
				{
				setState(366);
				py_content();
				}
				}
				setState(371);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(372);
			match(RPAREN);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Py_contentContext extends ParserRuleContext {
		public List<ReferenceContext> reference() {
			return getRuleContexts(ReferenceContext.class);
		}
		public ReferenceContext reference(int i) {
			return getRuleContext(ReferenceContext.class,i);
		}
		public List<RangeContext> range() {
			return getRuleContexts(RangeContext.class);
		}
		public RangeContext range(int i) {
			return getRuleContext(RangeContext.class,i);
		}
		public List<AnythingContext> anything() {
			return getRuleContexts(AnythingContext.class);
		}
		public AnythingContext anything(int i) {
			return getRuleContext(AnythingContext.class,i);
		}
		public List<TerminalNode> LPAREN() { return getTokens(dAngrParser.LPAREN); }
		public TerminalNode LPAREN(int i) {
			return getToken(dAngrParser.LPAREN, i);
		}
		public List<Py_contentContext> py_content() {
			return getRuleContexts(Py_contentContext.class);
		}
		public Py_contentContext py_content(int i) {
			return getRuleContext(Py_contentContext.class,i);
		}
		public List<TerminalNode> RPAREN() { return getTokens(dAngrParser.RPAREN); }
		public TerminalNode RPAREN(int i) {
			return getToken(dAngrParser.RPAREN, i);
		}
		public Py_contentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_py_content; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterPy_content(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitPy_content(this);
		}
	}

	public final Py_contentContext py_content() throws RecognitionException {
		Py_contentContext _localctx = new Py_contentContext(_ctx, getState());
		enterRule(_localctx, 34, RULE_py_content);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(381); 
			_errHandler.sync(this);
			_alt = 1;
			do {
				switch (_alt) {
				case 1:
					{
					setState(381);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,54,_ctx) ) {
					case 1:
						{
						setState(374);
						reference();
						}
						break;
					case 2:
						{
						setState(375);
						range();
						}
						break;
					case 3:
						{
						setState(376);
						anything();
						}
						break;
					case 4:
						{
						setState(377);
						match(LPAREN);
						setState(378);
						py_content();
						setState(379);
						match(RPAREN);
						}
						break;
					}
					}
					break;
				default:
					throw new NoViableAltException(this);
				}
				setState(383); 
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,55,_ctx);
			} while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER );
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Bash_contentContext extends ParserRuleContext {
		public List<ReferenceContext> reference() {
			return getRuleContexts(ReferenceContext.class);
		}
		public ReferenceContext reference(int i) {
			return getRuleContext(ReferenceContext.class,i);
		}
		public List<RangeContext> range() {
			return getRuleContexts(RangeContext.class);
		}
		public RangeContext range(int i) {
			return getRuleContext(RangeContext.class,i);
		}
		public List<AnythingContext> anything() {
			return getRuleContexts(AnythingContext.class);
		}
		public AnythingContext anything(int i) {
			return getRuleContext(AnythingContext.class,i);
		}
		public List<TerminalNode> LPAREN() { return getTokens(dAngrParser.LPAREN); }
		public TerminalNode LPAREN(int i) {
			return getToken(dAngrParser.LPAREN, i);
		}
		public List<Bash_contentContext> bash_content() {
			return getRuleContexts(Bash_contentContext.class);
		}
		public Bash_contentContext bash_content(int i) {
			return getRuleContext(Bash_contentContext.class,i);
		}
		public List<TerminalNode> RPAREN() { return getTokens(dAngrParser.RPAREN); }
		public TerminalNode RPAREN(int i) {
			return getToken(dAngrParser.RPAREN, i);
		}
		public Bash_contentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_bash_content; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterBash_content(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitBash_content(this);
		}
	}

	public final Bash_contentContext bash_content() throws RecognitionException {
		Bash_contentContext _localctx = new Bash_contentContext(_ctx, getState());
		enterRule(_localctx, 36, RULE_bash_content);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(394);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while ((((_la) & ~0x3f) == 0 && ((1L << _la) & -204022087682L) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & 8191L) != 0)) {
				{
				setState(392);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,56,_ctx) ) {
				case 1:
					{
					setState(385);
					reference();
					}
					break;
				case 2:
					{
					setState(386);
					range();
					}
					break;
				case 3:
					{
					setState(387);
					anything();
					}
					break;
				case 4:
					{
					setState(388);
					match(LPAREN);
					setState(389);
					bash_content();
					setState(390);
					match(RPAREN);
					}
					break;
				}
				}
				setState(396);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ReferenceContext extends ParserRuleContext {
		public TerminalNode DOT() { return getToken(dAngrParser.DOT, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public TerminalNode VARS_DB() { return getToken(dAngrParser.VARS_DB, 0); }
		public TerminalNode REG_DB() { return getToken(dAngrParser.REG_DB, 0); }
		public TerminalNode SYM_DB() { return getToken(dAngrParser.SYM_DB, 0); }
		public TerminalNode BANG() { return getToken(dAngrParser.BANG, 0); }
		public TerminalNode STATE() { return getToken(dAngrParser.STATE, 0); }
		public TerminalNode MEM_DB() { return getToken(dAngrParser.MEM_DB, 0); }
		public TerminalNode BRA() { return getToken(dAngrParser.BRA, 0); }
		public List<IndexContext> index() {
			return getRuleContexts(IndexContext.class);
		}
		public IndexContext index(int i) {
			return getRuleContext(IndexContext.class,i);
		}
		public TerminalNode KET() { return getToken(dAngrParser.KET, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public TerminalNode ARROW() { return getToken(dAngrParser.ARROW, 0); }
		public ReferenceContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_reference; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterReference(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitReference(this);
		}
	}

	public final ReferenceContext reference() throws RecognitionException {
		ReferenceContext _localctx = new ReferenceContext(_ctx, getState());
		enterRule(_localctx, 38, RULE_reference);
		int _la;
		try {
			setState(424);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case SYM_DB:
			case REG_DB:
			case VARS_DB:
				enterOuterAlt(_localctx, 1);
				{
				setState(397);
				_la = _input.LA(1);
				if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 117440512L) != 0)) ) {
				_errHandler.recoverInline(this);
				}
				else {
					if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
					_errHandler.reportMatch(this);
					consume();
				}
				setState(398);
				match(DOT);
				setState(399);
				identifier();
				setState(401);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,58,_ctx) ) {
				case 1:
					{
					setState(400);
					match(BANG);
					}
					break;
				}
				}
				break;
			case STATE:
				enterOuterAlt(_localctx, 2);
				{
				setState(403);
				match(STATE);
				}
				break;
			case MEM_DB:
				enterOuterAlt(_localctx, 3);
				{
				setState(404);
				match(MEM_DB);
				setState(405);
				match(BRA);
				setState(407);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(406);
					match(WS);
					}
				}

				setState(409);
				index();
				setState(418);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS || _la==ARROW) {
					{
					setState(411);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(410);
						match(WS);
						}
					}

					setState(413);
					match(ARROW);
					setState(415);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(414);
						match(WS);
						}
					}

					setState(417);
					index();
					}
				}

				setState(420);
				match(KET);
				setState(422);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,63,_ctx) ) {
				case 1:
					{
					setState(421);
					match(BANG);
					}
					break;
				}
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class IndexContext extends ParserRuleContext {
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public TerminalNode DASH() { return getToken(dAngrParser.DASH, 0); }
		public IndexContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_index; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterIndex(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitIndex(this);
		}
	}

	public final IndexContext index() throws RecognitionException {
		IndexContext _localctx = new IndexContext(_ctx, getState());
		enterRule(_localctx, 40, RULE_index);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(427);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,65,_ctx) ) {
			case 1:
				{
				setState(426);
				match(DASH);
				}
				break;
			}
			setState(429);
			expression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class IdentifierContext extends ParserRuleContext {
		public List<TerminalNode> LETTERS() { return getTokens(dAngrParser.LETTERS); }
		public TerminalNode LETTERS(int i) {
			return getToken(dAngrParser.LETTERS, i);
		}
		public List<TerminalNode> UNDERSCORE() { return getTokens(dAngrParser.UNDERSCORE); }
		public TerminalNode UNDERSCORE(int i) {
			return getToken(dAngrParser.UNDERSCORE, i);
		}
		public List<Special_wordsContext> special_words() {
			return getRuleContexts(Special_wordsContext.class);
		}
		public Special_wordsContext special_words(int i) {
			return getRuleContext(Special_wordsContext.class,i);
		}
		public List<TerminalNode> NUMBERS() { return getTokens(dAngrParser.NUMBERS); }
		public TerminalNode NUMBERS(int i) {
			return getToken(dAngrParser.NUMBERS, i);
		}
		public IdentifierContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_identifier; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterIdentifier(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitIdentifier(this);
		}
	}

	public final IdentifierContext identifier() throws RecognitionException {
		IdentifierContext _localctx = new IdentifierContext(_ctx, getState());
		enterRule(_localctx, 42, RULE_identifier);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(436);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case LETTERS:
				{
				setState(431);
				match(LETTERS);
				}
				break;
			case UNDERSCORE:
				{
				setState(432);
				match(UNDERSCORE);
				}
				break;
			case STATIC:
			case CIF:
			case CTHEN:
			case CELSE:
			case RANGE:
			case DEF:
			case IF:
			case ELSE:
			case FOR:
			case IN:
			case WHILE:
			case BOOL:
			case HELP:
			case RETURN:
			case BREAK:
			case CONTINUE:
				{
				setState(433);
				special_words();
				setState(434);
				match(UNDERSCORE);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			setState(444);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,68,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					setState(442);
					_errHandler.sync(this);
					switch (_input.LA(1)) {
					case LETTERS:
						{
						setState(438);
						match(LETTERS);
						}
						break;
					case NUMBERS:
						{
						setState(439);
						match(NUMBERS);
						}
						break;
					case UNDERSCORE:
						{
						setState(440);
						match(UNDERSCORE);
						}
						break;
					case STATIC:
					case CIF:
					case CTHEN:
					case CELSE:
					case RANGE:
					case DEF:
					case IF:
					case ELSE:
					case FOR:
					case IN:
					case WHILE:
					case BOOL:
					case HELP:
					case RETURN:
					case BREAK:
					case CONTINUE:
						{
						setState(441);
						special_words();
						}
						break;
					default:
						throw new NoViableAltException(this);
					}
					} 
				}
				setState(446);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,68,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class NumericContext extends ParserRuleContext {
		public TerminalNode NUMBERS() { return getToken(dAngrParser.NUMBERS, 0); }
		public TerminalNode HEX_NUMBERS() { return getToken(dAngrParser.HEX_NUMBERS, 0); }
		public NumericContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_numeric; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterNumeric(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitNumeric(this);
		}
	}

	public final NumericContext numeric() throws RecognitionException {
		NumericContext _localctx = new NumericContext(_ctx, getState());
		enterRule(_localctx, 44, RULE_numeric);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(447);
			_la = _input.LA(1);
			if ( !(_la==HEX_NUMBERS || _la==NUMBERS) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ObjectContext extends ParserRuleContext {
		public ObjectContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_object; }
	 
		public ObjectContext() { }
		public void copyFrom(ObjectContext ctx) {
			super.copyFrom(ctx);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SlideStartLengthObjectContext extends ObjectContext {
		public ObjectContext object() {
			return getRuleContext(ObjectContext.class,0);
		}
		public TerminalNode BRA() { return getToken(dAngrParser.BRA, 0); }
		public List<IndexContext> index() {
			return getRuleContexts(IndexContext.class);
		}
		public IndexContext index(int i) {
			return getRuleContext(IndexContext.class,i);
		}
		public TerminalNode ARROW() { return getToken(dAngrParser.ARROW, 0); }
		public TerminalNode KET() { return getToken(dAngrParser.KET, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public SlideStartLengthObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterSlideStartLengthObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitSlideStartLengthObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ReferenceObjectContext extends ObjectContext {
		public ReferenceContext reference() {
			return getRuleContext(ReferenceContext.class,0);
		}
		public ReferenceObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterReferenceObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitReferenceObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class BinaryStringObjectContext extends ObjectContext {
		public TerminalNode BINARY_STRING() { return getToken(dAngrParser.BINARY_STRING, 0); }
		public BinaryStringObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterBinaryStringObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitBinaryStringObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ListObjectContext extends ObjectContext {
		public TerminalNode BRA() { return getToken(dAngrParser.BRA, 0); }
		public TerminalNode KET() { return getToken(dAngrParser.KET, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public List<ObjectContext> object() {
			return getRuleContexts(ObjectContext.class);
		}
		public ObjectContext object(int i) {
			return getRuleContext(ObjectContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(dAngrParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(dAngrParser.COMMA, i);
		}
		public ListObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterListObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitListObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class IndexedPropertyObjectContext extends ObjectContext {
		public ObjectContext object() {
			return getRuleContext(ObjectContext.class,0);
		}
		public TerminalNode BRA() { return getToken(dAngrParser.BRA, 0); }
		public IndexContext index() {
			return getRuleContext(IndexContext.class,0);
		}
		public TerminalNode KET() { return getToken(dAngrParser.KET, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public IndexedPropertyObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterIndexedPropertyObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitIndexedPropertyObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class DictionaryObjectContext extends ObjectContext {
		public TerminalNode BRACE() { return getToken(dAngrParser.BRACE, 0); }
		public TerminalNode KETCE() { return getToken(dAngrParser.KETCE, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public List<TerminalNode> STRING() { return getTokens(dAngrParser.STRING); }
		public TerminalNode STRING(int i) {
			return getToken(dAngrParser.STRING, i);
		}
		public List<TerminalNode> COLON() { return getTokens(dAngrParser.COLON); }
		public TerminalNode COLON(int i) {
			return getToken(dAngrParser.COLON, i);
		}
		public List<ObjectContext> object() {
			return getRuleContexts(ObjectContext.class);
		}
		public ObjectContext object(int i) {
			return getRuleContext(ObjectContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(dAngrParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(dAngrParser.COMMA, i);
		}
		public DictionaryObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterDictionaryObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitDictionaryObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class NumericObjectContext extends ObjectContext {
		public NumericContext numeric() {
			return getRuleContext(NumericContext.class,0);
		}
		public TerminalNode DASH() { return getToken(dAngrParser.DASH, 0); }
		public NumericObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterNumericObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitNumericObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SliceStartEndObjectContext extends ObjectContext {
		public ObjectContext object() {
			return getRuleContext(ObjectContext.class,0);
		}
		public TerminalNode BRA() { return getToken(dAngrParser.BRA, 0); }
		public List<IndexContext> index() {
			return getRuleContexts(IndexContext.class);
		}
		public IndexContext index(int i) {
			return getRuleContext(IndexContext.class,i);
		}
		public TerminalNode COLON() { return getToken(dAngrParser.COLON, 0); }
		public TerminalNode KET() { return getToken(dAngrParser.KET, 0); }
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
		public SliceStartEndObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterSliceStartEndObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitSliceStartEndObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class StringObjectContext extends ObjectContext {
		public TerminalNode STRING() { return getToken(dAngrParser.STRING, 0); }
		public StringObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterStringObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitStringObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class IDObjectContext extends ObjectContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public TerminalNode BANG() { return getToken(dAngrParser.BANG, 0); }
		public IDObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterIDObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitIDObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class PropertyObjectContext extends ObjectContext {
		public ObjectContext object() {
			return getRuleContext(ObjectContext.class,0);
		}
		public TerminalNode DOT() { return getToken(dAngrParser.DOT, 0); }
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public PropertyObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterPropertyObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitPropertyObject(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class BoolObjectContext extends ObjectContext {
		public TerminalNode BOOL() { return getToken(dAngrParser.BOOL, 0); }
		public BoolObjectContext(ObjectContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterBoolObject(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitBoolObject(this);
		}
	}

	public final ObjectContext object() throws RecognitionException {
		return object(0);
	}

	private ObjectContext object(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		ObjectContext _localctx = new ObjectContext(_ctx, _parentState);
		ObjectContext _prevctx = _localctx;
		int _startState = 46;
		enterRecursionRule(_localctx, 46, RULE_object, _p);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(525);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,86,_ctx) ) {
			case 1:
				{
				_localctx = new IDObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(450);
				identifier();
				setState(452);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,69,_ctx) ) {
				case 1:
					{
					setState(451);
					match(BANG);
					}
					break;
				}
				}
				break;
			case 2:
				{
				_localctx = new NumericObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(455);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==DASH) {
					{
					setState(454);
					match(DASH);
					}
				}

				setState(457);
				numeric();
				}
				break;
			case 3:
				{
				_localctx = new BoolObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(458);
				match(BOOL);
				}
				break;
			case 4:
				{
				_localctx = new ReferenceObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(459);
				reference();
				}
				break;
			case 5:
				{
				_localctx = new ListObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(460);
				match(BRA);
				setState(462);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,71,_ctx) ) {
				case 1:
					{
					setState(461);
					match(WS);
					}
					break;
				}
				setState(465);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 2814751903711230L) != 0) || _la==UNDERSCORE || _la==DASH) {
					{
					setState(464);
					object(0);
					}
				}

				setState(477);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,75,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(468);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(467);
							match(WS);
							}
						}

						setState(470);
						match(COMMA);
						setState(472);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(471);
							match(WS);
							}
						}

						setState(474);
						object(0);
						}
						} 
					}
					setState(479);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,75,_ctx);
				}
				setState(481);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(480);
					match(WS);
					}
				}

				setState(483);
				match(KET);
				}
				break;
			case 6:
				{
				_localctx = new DictionaryObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(484);
				match(BRACE);
				setState(486);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,77,_ctx) ) {
				case 1:
					{
					setState(485);
					match(WS);
					}
					break;
				}
				setState(516);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==STRING) {
					{
					{
					setState(488);
					match(STRING);
					setState(490);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(489);
						match(WS);
						}
					}

					setState(492);
					match(COLON);
					setState(494);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(493);
						match(WS);
						}
					}

					setState(496);
					object(0);
					{
					setState(498);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(497);
						match(WS);
						}
					}

					setState(500);
					match(COMMA);
					setState(502);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(501);
						match(WS);
						}
					}

					setState(504);
					match(STRING);
					setState(506);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(505);
						match(WS);
						}
					}

					setState(508);
					match(COLON);
					setState(510);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(509);
						match(WS);
						}
					}

					setState(512);
					object(0);
					}
					}
					}
					setState(518);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(520);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(519);
					match(WS);
					}
				}

				setState(522);
				match(KETCE);
				}
				break;
			case 7:
				{
				_localctx = new StringObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(523);
				match(STRING);
				}
				break;
			case 8:
				{
				_localctx = new BinaryStringObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(524);
				match(BINARY_STRING);
				}
				break;
			}
			_ctx.stop = _input.LT(-1);
			setState(583);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,99,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					setState(581);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,98,_ctx) ) {
					case 1:
						{
						_localctx = new PropertyObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(527);
						if (!(precpred(_ctx, 8))) throw new FailedPredicateException(this, "precpred(_ctx, 8)");
						setState(528);
						match(DOT);
						setState(529);
						identifier();
						}
						break;
					case 2:
						{
						_localctx = new IndexedPropertyObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(530);
						if (!(precpred(_ctx, 7))) throw new FailedPredicateException(this, "precpred(_ctx, 7)");
						setState(531);
						match(BRA);
						setState(533);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(532);
							match(WS);
							}
						}

						setState(535);
						index();
						setState(537);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(536);
							match(WS);
							}
						}

						setState(539);
						match(KET);
						}
						break;
					case 3:
						{
						_localctx = new SliceStartEndObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(541);
						if (!(precpred(_ctx, 6))) throw new FailedPredicateException(this, "precpred(_ctx, 6)");
						setState(542);
						match(BRA);
						setState(544);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(543);
							match(WS);
							}
						}

						setState(546);
						index();
						setState(548);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(547);
							match(WS);
							}
						}

						setState(550);
						match(COLON);
						setState(552);
						_errHandler.sync(this);
						switch ( getInterpreter().adaptivePredict(_input,91,_ctx) ) {
						case 1:
							{
							setState(551);
							match(WS);
							}
							break;
						}
						setState(555);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 2816744768536574L) != 0) || _la==UNDERSCORE || _la==DASH) {
							{
							setState(554);
							index();
							}
						}

						setState(558);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(557);
							match(WS);
							}
						}

						setState(560);
						match(KET);
						}
						break;
					case 4:
						{
						_localctx = new SlideStartLengthObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(562);
						if (!(precpred(_ctx, 5))) throw new FailedPredicateException(this, "precpred(_ctx, 5)");
						setState(563);
						match(BRA);
						setState(565);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(564);
							match(WS);
							}
						}

						setState(567);
						index();
						setState(569);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(568);
							match(WS);
							}
						}

						setState(571);
						match(ARROW);
						setState(573);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(572);
							match(WS);
							}
						}

						setState(575);
						index();
						setState(577);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(576);
							match(WS);
							}
						}

						setState(579);
						match(KET);
						}
						break;
					}
					} 
				}
				setState(585);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,99,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class AnythingContext extends ParserRuleContext {
		public TerminalNode LETTERS() { return getToken(dAngrParser.LETTERS, 0); }
		public TerminalNode NUMBERS() { return getToken(dAngrParser.NUMBERS, 0); }
		public SymbolContext symbol() {
			return getRuleContext(SymbolContext.class,0);
		}
		public TerminalNode STRING() { return getToken(dAngrParser.STRING, 0); }
		public TerminalNode BINARY_STRING() { return getToken(dAngrParser.BINARY_STRING, 0); }
		public TerminalNode WS() { return getToken(dAngrParser.WS, 0); }
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public AnythingContext anything() {
			return getRuleContext(AnythingContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public Special_wordsContext special_words() {
			return getRuleContext(Special_wordsContext.class,0);
		}
		public AnythingContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_anything; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterAnything(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitAnything(this);
		}
	}

	public final AnythingContext anything() throws RecognitionException {
		AnythingContext _localctx = new AnythingContext(_ctx, getState());
		enterRule(_localctx, 48, RULE_anything);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(597);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,100,_ctx) ) {
			case 1:
				{
				setState(586);
				match(LETTERS);
				}
				break;
			case 2:
				{
				setState(587);
				match(NUMBERS);
				}
				break;
			case 3:
				{
				setState(588);
				symbol();
				}
				break;
			case 4:
				{
				setState(589);
				match(STRING);
				}
				break;
			case 5:
				{
				setState(590);
				match(BINARY_STRING);
				}
				break;
			case 6:
				{
				setState(591);
				match(WS);
				}
				break;
			case 7:
				{
				setState(592);
				match(LPAREN);
				setState(593);
				anything();
				setState(594);
				match(RPAREN);
				}
				break;
			case 8:
				{
				setState(596);
				special_words();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Special_wordsContext extends ParserRuleContext {
		public TerminalNode STATIC() { return getToken(dAngrParser.STATIC, 0); }
		public TerminalNode DEF() { return getToken(dAngrParser.DEF, 0); }
		public TerminalNode IF() { return getToken(dAngrParser.IF, 0); }
		public TerminalNode ELSE() { return getToken(dAngrParser.ELSE, 0); }
		public TerminalNode FOR() { return getToken(dAngrParser.FOR, 0); }
		public TerminalNode IN() { return getToken(dAngrParser.IN, 0); }
		public TerminalNode WHILE() { return getToken(dAngrParser.WHILE, 0); }
		public TerminalNode BOOL() { return getToken(dAngrParser.BOOL, 0); }
		public TerminalNode HELP() { return getToken(dAngrParser.HELP, 0); }
		public TerminalNode CIF() { return getToken(dAngrParser.CIF, 0); }
		public TerminalNode CTHEN() { return getToken(dAngrParser.CTHEN, 0); }
		public TerminalNode CELSE() { return getToken(dAngrParser.CELSE, 0); }
		public TerminalNode RETURN() { return getToken(dAngrParser.RETURN, 0); }
		public TerminalNode BREAK() { return getToken(dAngrParser.BREAK, 0); }
		public TerminalNode CONTINUE() { return getToken(dAngrParser.CONTINUE, 0); }
		public TerminalNode RANGE() { return getToken(dAngrParser.RANGE, 0); }
		public Special_wordsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_special_words; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterSpecial_words(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitSpecial_words(this);
		}
	}

	public final Special_wordsContext special_words() throws RecognitionException {
		Special_wordsContext _localctx = new Special_wordsContext(_ctx, getState());
		enterRule(_localctx, 50, RULE_special_words);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(599);
			_la = _input.LA(1);
			if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 131070L) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class RangeContext extends ParserRuleContext {
		public Dangr_rangeContext dangr_range() {
			return getRuleContext(Dangr_rangeContext.class,0);
		}
		public Bash_rangeContext bash_range() {
			return getRuleContext(Bash_rangeContext.class,0);
		}
		public Python_rangeContext python_range() {
			return getRuleContext(Python_rangeContext.class,0);
		}
		public RangeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_range; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterRange(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitRange(this);
		}
	}

	public final RangeContext range() throws RecognitionException {
		RangeContext _localctx = new RangeContext(_ctx, getState());
		enterRule(_localctx, 52, RULE_range);
		try {
			setState(604);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case AMP:
				enterOuterAlt(_localctx, 1);
				{
				setState(601);
				dangr_range();
				}
				break;
			case DOLLAR:
				enterOuterAlt(_localctx, 2);
				{
				setState(602);
				bash_range();
				}
				break;
			case BANG:
				enterOuterAlt(_localctx, 3);
				{
				setState(603);
				python_range();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Dangr_rangeContext extends ParserRuleContext {
		public TerminalNode AMP() { return getToken(dAngrParser.AMP, 0); }
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public Dangr_rangeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_dangr_range; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterDangr_range(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitDangr_range(this);
		}
	}

	public final Dangr_rangeContext dangr_range() throws RecognitionException {
		Dangr_rangeContext _localctx = new Dangr_rangeContext(_ctx, getState());
		enterRule(_localctx, 54, RULE_dangr_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(606);
			match(AMP);
			setState(607);
			match(LPAREN);
			setState(608);
			expression();
			setState(609);
			match(RPAREN);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Bash_rangeContext extends ParserRuleContext {
		public TerminalNode DOLLAR() { return getToken(dAngrParser.DOLLAR, 0); }
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public Bash_contentContext bash_content() {
			return getRuleContext(Bash_contentContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public Bash_rangeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_bash_range; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterBash_range(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitBash_range(this);
		}
	}

	public final Bash_rangeContext bash_range() throws RecognitionException {
		Bash_rangeContext _localctx = new Bash_rangeContext(_ctx, getState());
		enterRule(_localctx, 56, RULE_bash_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(611);
			match(DOLLAR);
			setState(612);
			match(LPAREN);
			setState(613);
			bash_content();
			setState(614);
			match(RPAREN);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class Python_rangeContext extends ParserRuleContext {
		public TerminalNode BANG() { return getToken(dAngrParser.BANG, 0); }
		public TerminalNode LPAREN() { return getToken(dAngrParser.LPAREN, 0); }
		public Py_contentContext py_content() {
			return getRuleContext(Py_contentContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(dAngrParser.RPAREN, 0); }
		public Python_rangeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_python_range; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterPython_range(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitPython_range(this);
		}
	}

	public final Python_rangeContext python_range() throws RecognitionException {
		Python_rangeContext _localctx = new Python_rangeContext(_ctx, getState());
		enterRule(_localctx, 58, RULE_python_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(616);
			match(BANG);
			setState(617);
			match(LPAREN);
			setState(618);
			py_content();
			setState(619);
			match(RPAREN);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class SymbolContext extends ParserRuleContext {
		public TerminalNode WS() { return getToken(dAngrParser.WS, 0); }
		public TerminalNode BANG() { return getToken(dAngrParser.BANG, 0); }
		public TerminalNode AMP() { return getToken(dAngrParser.AMP, 0); }
		public TerminalNode DOLLAR() { return getToken(dAngrParser.DOLLAR, 0); }
		public TerminalNode COLON() { return getToken(dAngrParser.COLON, 0); }
		public TerminalNode SCOLON() { return getToken(dAngrParser.SCOLON, 0); }
		public TerminalNode COMMA() { return getToken(dAngrParser.COMMA, 0); }
		public TerminalNode QUOTE() { return getToken(dAngrParser.QUOTE, 0); }
		public TerminalNode SQUOTE() { return getToken(dAngrParser.SQUOTE, 0); }
		public TerminalNode AT() { return getToken(dAngrParser.AT, 0); }
		public TerminalNode DOT() { return getToken(dAngrParser.DOT, 0); }
		public TerminalNode BAR() { return getToken(dAngrParser.BAR, 0); }
		public TerminalNode BRA() { return getToken(dAngrParser.BRA, 0); }
		public TerminalNode KET() { return getToken(dAngrParser.KET, 0); }
		public TerminalNode BRACE() { return getToken(dAngrParser.BRACE, 0); }
		public TerminalNode KETCE() { return getToken(dAngrParser.KETCE, 0); }
		public TerminalNode HAT() { return getToken(dAngrParser.HAT, 0); }
		public TerminalNode HASH() { return getToken(dAngrParser.HASH, 0); }
		public TerminalNode PERC() { return getToken(dAngrParser.PERC, 0); }
		public TerminalNode MUL() { return getToken(dAngrParser.MUL, 0); }
		public TerminalNode ADD() { return getToken(dAngrParser.ADD, 0); }
		public TerminalNode DIV() { return getToken(dAngrParser.DIV, 0); }
		public TerminalNode POW() { return getToken(dAngrParser.POW, 0); }
		public TerminalNode ASSIGN() { return getToken(dAngrParser.ASSIGN, 0); }
		public TerminalNode EQ() { return getToken(dAngrParser.EQ, 0); }
		public TerminalNode NEQ() { return getToken(dAngrParser.NEQ, 0); }
		public TerminalNode LT() { return getToken(dAngrParser.LT, 0); }
		public TerminalNode GT() { return getToken(dAngrParser.GT, 0); }
		public TerminalNode LE() { return getToken(dAngrParser.LE, 0); }
		public TerminalNode GE() { return getToken(dAngrParser.GE, 0); }
		public TerminalNode AND() { return getToken(dAngrParser.AND, 0); }
		public TerminalNode OR() { return getToken(dAngrParser.OR, 0); }
		public TerminalNode QMARK() { return getToken(dAngrParser.QMARK, 0); }
		public TerminalNode TILDE() { return getToken(dAngrParser.TILDE, 0); }
		public TerminalNode TICK() { return getToken(dAngrParser.TICK, 0); }
		public TerminalNode UNDERSCORE() { return getToken(dAngrParser.UNDERSCORE, 0); }
		public TerminalNode DASH() { return getToken(dAngrParser.DASH, 0); }
		public TerminalNode FLOORDIV() { return getToken(dAngrParser.FLOORDIV, 0); }
		public TerminalNode LSHIFT() { return getToken(dAngrParser.LSHIFT, 0); }
		public TerminalNode RSHIFT() { return getToken(dAngrParser.RSHIFT, 0); }
		public SymbolContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_symbol; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterSymbol(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitSymbol(this);
		}
	}

	public final SymbolContext symbol() throws RecognitionException {
		SymbolContext _localctx = new SymbolContext(_ctx, getState());
		enterRule(_localctx, 60, RULE_symbol);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(621);
			_la = _input.LA(1);
			if ( !(((((_la - 18)) & ~0x3f) == 0 && ((1L << (_la - 18)) & 576460752302374913L) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public boolean sempred(RuleContext _localctx, int ruleIndex, int predIndex) {
		switch (ruleIndex) {
		case 3:
			return expression_part_sempred((Expression_partContext)_localctx, predIndex);
		case 23:
			return object_sempred((ObjectContext)_localctx, predIndex);
		}
		return true;
	}
	private boolean expression_part_sempred(Expression_partContext _localctx, int predIndex) {
		switch (predIndex) {
		case 0:
			return precpred(_ctx, 6);
		}
		return true;
	}
	private boolean object_sempred(ObjectContext _localctx, int predIndex) {
		switch (predIndex) {
		case 1:
			return precpred(_ctx, 8);
		case 2:
			return precpred(_ctx, 7);
		case 3:
			return precpred(_ctx, 6);
		case 4:
			return precpred(_ctx, 5);
		}
		return true;
	}

	public static final String _serializedATN =
		"\u0004\u0001N\u0270\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0002"+
		"\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004\u0002"+
		"\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007\u0007\u0007\u0002"+
		"\b\u0007\b\u0002\t\u0007\t\u0002\n\u0007\n\u0002\u000b\u0007\u000b\u0002"+
		"\f\u0007\f\u0002\r\u0007\r\u0002\u000e\u0007\u000e\u0002\u000f\u0007\u000f"+
		"\u0002\u0010\u0007\u0010\u0002\u0011\u0007\u0011\u0002\u0012\u0007\u0012"+
		"\u0002\u0013\u0007\u0013\u0002\u0014\u0007\u0014\u0002\u0015\u0007\u0015"+
		"\u0002\u0016\u0007\u0016\u0002\u0017\u0007\u0017\u0002\u0018\u0007\u0018"+
		"\u0002\u0019\u0007\u0019\u0002\u001a\u0007\u001a\u0002\u001b\u0007\u001b"+
		"\u0002\u001c\u0007\u001c\u0002\u001d\u0007\u001d\u0002\u001e\u0007\u001e"+
		"\u0001\u0000\u0001\u0000\u0001\u0000\u0003\u0000B\b\u0000\u0001\u0000"+
		"\u0001\u0000\u0001\u0000\u0001\u0000\u0005\u0000H\b\u0000\n\u0000\f\u0000"+
		"K\t\u0000\u0003\u0000M\b\u0000\u0001\u0000\u0001\u0000\u0001\u0001\u0001"+
		"\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001"+
		"\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0003"+
		"\u0001^\b\u0001\u0001\u0002\u0001\u0002\u0001\u0002\u0003\u0002c\b\u0002"+
		"\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0003\u0002"+
		"j\b\u0002\u0001\u0002\u0005\u0002m\b\u0002\n\u0002\f\u0002p\t\u0002\u0001"+
		"\u0002\u0003\u0002s\b\u0002\u0001\u0003\u0001\u0003\u0001\u0003\u0003"+
		"\u0003x\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003|\b\u0003\u0001\u0003"+
		"\u0001\u0003\u0003\u0003\u0080\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003"+
		"\u0084\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u0088\b\u0003\u0001"+
		"\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u008e\b\u0003\u0001"+
		"\u0003\u0001\u0003\u0003\u0003\u0092\b\u0003\u0001\u0003\u0001\u0003\u0001"+
		"\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u0099\b\u0003\u0001\u0003\u0001"+
		"\u0003\u0003\u0003\u009d\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00a1"+
		"\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00a5\b\u0003\u0001\u0003"+
		"\u0001\u0003\u0003\u0003\u00a9\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003"+
		"\u00ad\b\u0003\u0003\u0003\u00af\b\u0003\u0003\u0003\u00b1\b\u0003\u0001"+
		"\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001"+
		"\u0003\u0003\u0003\u00ba\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00be"+
		"\b\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00c3\b\u0003"+
		"\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0005\u0003"+
		"\u00ca\b\u0003\n\u0003\f\u0003\u00cd\t\u0003\u0001\u0004\u0001\u0004\u0003"+
		"\u0004\u00d1\b\u0004\u0001\u0004\u0003\u0004\u00d4\b\u0004\u0001\u0004"+
		"\u0001\u0004\u0003\u0004\u00d8\b\u0004\u0001\u0004\u0001\u0004\u0001\u0005"+
		"\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0006\u0001\u0006\u0001\u0006"+
		"\u0001\u0006\u0001\u0006\u0001\u0006\u0003\u0006\u00e6\b\u0006\u0001\u0007"+
		"\u0001\u0007\u0001\u0007\u0001\u0007\u0003\u0007\u00ec\b\u0007\u0001\u0007"+
		"\u0001\u0007\u0001\u0007\u0003\u0007\u00f1\b\u0007\u0001\u0007\u0001\u0007"+
		"\u0001\u0007\u0001\u0007\u0003\u0007\u00f7\b\u0007\u0001\u0007\u0001\u0007"+
		"\u0003\u0007\u00fb\b\u0007\u0001\u0007\u0003\u0007\u00fe\b\u0007\u0001"+
		"\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0003\u0007\u0105"+
		"\b\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001"+
		"\u0007\u0001\u0007\u0003\u0007\u010e\b\u0007\u0001\u0007\u0001\u0007\u0001"+
		"\u0007\u0003\u0007\u0113\b\u0007\u0001\b\u0001\b\u0003\b\u0117\b\b\u0001"+
		"\b\u0001\b\u0001\b\u0001\t\u0001\t\u0001\t\u0001\t\u0003\t\u0120\b\t\u0001"+
		"\t\u0001\t\u0003\t\u0124\b\t\u0001\t\u0001\t\u0003\t\u0128\b\t\u0001\t"+
		"\u0001\t\u0001\t\u0001\n\u0001\n\u0001\n\u0003\n\u0130\b\n\u0004\n\u0132"+
		"\b\n\u000b\n\f\n\u0133\u0001\n\u0001\n\u0001\u000b\u0001\u000b\u0001\u000b"+
		"\u0001\u000b\u0001\u000b\u0001\u000b\u0003\u000b\u013e\b\u000b\u0001\f"+
		"\u0001\f\u0001\r\u0001\r\u0003\r\u0144\b\r\u0001\r\u0001\r\u0003\r\u0148"+
		"\b\r\u0001\r\u0005\r\u014b\b\r\n\r\f\r\u014e\t\r\u0001\u000e\u0001\u000e"+
		"\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f"+
		"\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f"+
		"\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f"+
		"\u0001\u000f\u0003\u000f\u0165\b\u000f\u0001\u0010\u0001\u0010\u0003\u0010"+
		"\u0169\b\u0010\u0001\u0010\u0001\u0010\u0003\u0010\u016d\b\u0010\u0001"+
		"\u0010\u0005\u0010\u0170\b\u0010\n\u0010\f\u0010\u0173\t\u0010\u0001\u0010"+
		"\u0001\u0010\u0001\u0011\u0001\u0011\u0001\u0011\u0001\u0011\u0001\u0011"+
		"\u0001\u0011\u0001\u0011\u0004\u0011\u017e\b\u0011\u000b\u0011\f\u0011"+
		"\u017f\u0001\u0012\u0001\u0012\u0001\u0012\u0001\u0012\u0001\u0012\u0001"+
		"\u0012\u0001\u0012\u0005\u0012\u0189\b\u0012\n\u0012\f\u0012\u018c\t\u0012"+
		"\u0001\u0013\u0001\u0013\u0001\u0013\u0001\u0013\u0003\u0013\u0192\b\u0013"+
		"\u0001\u0013\u0001\u0013\u0001\u0013\u0001\u0013\u0003\u0013\u0198\b\u0013"+
		"\u0001\u0013\u0001\u0013\u0003\u0013\u019c\b\u0013\u0001\u0013\u0001\u0013"+
		"\u0003\u0013\u01a0\b\u0013\u0001\u0013\u0003\u0013\u01a3\b\u0013\u0001"+
		"\u0013\u0001\u0013\u0003\u0013\u01a7\b\u0013\u0003\u0013\u01a9\b\u0013"+
		"\u0001\u0014\u0003\u0014\u01ac\b\u0014\u0001\u0014\u0001\u0014\u0001\u0015"+
		"\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0015\u0003\u0015\u01b5\b\u0015"+
		"\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0015\u0005\u0015\u01bb\b\u0015"+
		"\n\u0015\f\u0015\u01be\t\u0015\u0001\u0016\u0001\u0016\u0001\u0017\u0001"+
		"\u0017\u0001\u0017\u0003\u0017\u01c5\b\u0017\u0001\u0017\u0003\u0017\u01c8"+
		"\b\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0003"+
		"\u0017\u01cf\b\u0017\u0001\u0017\u0003\u0017\u01d2\b\u0017\u0001\u0017"+
		"\u0003\u0017\u01d5\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u01d9\b"+
		"\u0017\u0001\u0017\u0005\u0017\u01dc\b\u0017\n\u0017\f\u0017\u01df\t\u0017"+
		"\u0001\u0017\u0003\u0017\u01e2\b\u0017\u0001\u0017\u0001\u0017\u0001\u0017"+
		"\u0003\u0017\u01e7\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u01eb\b"+
		"\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u01ef\b\u0017\u0001\u0017\u0001"+
		"\u0017\u0003\u0017\u01f3\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u01f7"+
		"\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u01fb\b\u0017\u0001\u0017"+
		"\u0001\u0017\u0003\u0017\u01ff\b\u0017\u0001\u0017\u0001\u0017\u0005\u0017"+
		"\u0203\b\u0017\n\u0017\f\u0017\u0206\t\u0017\u0001\u0017\u0003\u0017\u0209"+
		"\b\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u020e\b\u0017"+
		"\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017"+
		"\u0003\u0017\u0216\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u021a\b"+
		"\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0003"+
		"\u0017\u0221\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0225\b\u0017"+
		"\u0001\u0017\u0001\u0017\u0003\u0017\u0229\b\u0017\u0001\u0017\u0003\u0017"+
		"\u022c\b\u0017\u0001\u0017\u0003\u0017\u022f\b\u0017\u0001\u0017\u0001"+
		"\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0236\b\u0017\u0001"+
		"\u0017\u0001\u0017\u0003\u0017\u023a\b\u0017\u0001\u0017\u0001\u0017\u0003"+
		"\u0017\u023e\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0242\b\u0017"+
		"\u0001\u0017\u0001\u0017\u0005\u0017\u0246\b\u0017\n\u0017\f\u0017\u0249"+
		"\t\u0017\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001"+
		"\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0003"+
		"\u0018\u0256\b\u0018\u0001\u0019\u0001\u0019\u0001\u001a\u0001\u001a\u0001"+
		"\u001a\u0003\u001a\u025d\b\u001a\u0001\u001b\u0001\u001b\u0001\u001b\u0001"+
		"\u001b\u0001\u001b\u0001\u001c\u0001\u001c\u0001\u001c\u0001\u001c\u0001"+
		"\u001c\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001d\u0001"+
		"\u001e\u0001\u001e\u0001\u001e\u0000\u0002\u0006.\u001f\u0000\u0002\u0004"+
		"\u0006\b\n\f\u000e\u0010\u0012\u0014\u0016\u0018\u001a\u001c\u001e \""+
		"$&(*,.02468:<\u0000\u0005\u0002\u0000\r\rHH\u0001\u0000\u0018\u001a\u0001"+
		"\u0000\u0013\u0014\u0001\u0000\u0001\u0010\u0002\u0000\u0012\u0012&L\u02eb"+
		"\u0000L\u0001\u0000\u0000\u0000\u0002]\u0001\u0000\u0000\u0000\u0004r"+
		"\u0001\u0000\u0000\u0000\u0006\u00c2\u0001\u0000\u0000\u0000\b\u00d0\u0001"+
		"\u0000\u0000\u0000\n\u00db\u0001\u0000\u0000\u0000\f\u00e5\u0001\u0000"+
		"\u0000\u0000\u000e\u0112\u0001\u0000\u0000\u0000\u0010\u0114\u0001\u0000"+
		"\u0000\u0000\u0012\u011b\u0001\u0000\u0000\u0000\u0014\u012c\u0001\u0000"+
		"\u0000\u0000\u0016\u013d\u0001\u0000\u0000\u0000\u0018\u013f\u0001\u0000"+
		"\u0000\u0000\u001a\u0141\u0001\u0000\u0000\u0000\u001c\u014f\u0001\u0000"+
		"\u0000\u0000\u001e\u0164\u0001\u0000\u0000\u0000 \u0166\u0001\u0000\u0000"+
		"\u0000\"\u017d\u0001\u0000\u0000\u0000$\u018a\u0001\u0000\u0000\u0000"+
		"&\u01a8\u0001\u0000\u0000\u0000(\u01ab\u0001\u0000\u0000\u0000*\u01b4"+
		"\u0001\u0000\u0000\u0000,\u01bf\u0001\u0000\u0000\u0000.\u020d\u0001\u0000"+
		"\u0000\u00000\u0255\u0001\u0000\u0000\u00002\u0257\u0001\u0000\u0000\u0000"+
		"4\u025c\u0001\u0000\u0000\u00006\u025e\u0001\u0000\u0000\u00008\u0263"+
		"\u0001\u0000\u0000\u0000:\u0268\u0001\u0000\u0000\u0000<\u026d\u0001\u0000"+
		"\u0000\u0000>A\u0007\u0000\u0000\u0000?@\u0005\u0012\u0000\u0000@B\u0003"+
		"*\u0015\u0000A?\u0001\u0000\u0000\u0000AB\u0001\u0000\u0000\u0000BC\u0001"+
		"\u0000\u0000\u0000CM\u0005\u0011\u0000\u0000DH\u0005\u0011\u0000\u0000"+
		"EH\u0003\u0002\u0001\u0000FH\u0003\u0012\t\u0000GD\u0001\u0000\u0000\u0000"+
		"GE\u0001\u0000\u0000\u0000GF\u0001\u0000\u0000\u0000HK\u0001\u0000\u0000"+
		"\u0000IG\u0001\u0000\u0000\u0000IJ\u0001\u0000\u0000\u0000JM\u0001\u0000"+
		"\u0000\u0000KI\u0001\u0000\u0000\u0000L>\u0001\u0000\u0000\u0000LI\u0001"+
		"\u0000\u0000\u0000MN\u0001\u0000\u0000\u0000NO\u0005\u0000\u0000\u0001"+
		"O\u0001\u0001\u0000\u0000\u0000P^\u0003\u000e\u0007\u0000QR\u0003\b\u0004"+
		"\u0000RS\u0005\u0011\u0000\u0000S^\u0001\u0000\u0000\u0000TU\u0003\u0004"+
		"\u0002\u0000UV\u0005\u0011\u0000\u0000V^\u0001\u0000\u0000\u0000WX\u0003"+
		"\n\u0005\u0000XY\u0005\u0011\u0000\u0000Y^\u0001\u0000\u0000\u0000Z[\u0003"+
		"\f\u0006\u0000[\\\u0005\u0011\u0000\u0000\\^\u0001\u0000\u0000\u0000]"+
		"P\u0001\u0000\u0000\u0000]Q\u0001\u0000\u0000\u0000]T\u0001\u0000\u0000"+
		"\u0000]W\u0001\u0000\u0000\u0000]Z\u0001\u0000\u0000\u0000^\u0003\u0001"+
		"\u0000\u0000\u0000_`\u0003*\u0015\u0000`a\u0005/\u0000\u0000ac\u0001\u0000"+
		"\u0000\u0000b_\u0001\u0000\u0000\u0000bc\u0001\u0000\u0000\u0000cd\u0001"+
		"\u0000\u0000\u0000dn\u0003*\u0015\u0000ei\u0005\u0012\u0000\u0000fg\u0003"+
		"*\u0015\u0000gh\u0005?\u0000\u0000hj\u0001\u0000\u0000\u0000if\u0001\u0000"+
		"\u0000\u0000ij\u0001\u0000\u0000\u0000jk\u0001\u0000\u0000\u0000km\u0003"+
		"\u0006\u0003\u0000le\u0001\u0000\u0000\u0000mp\u0001\u0000\u0000\u0000"+
		"nl\u0001\u0000\u0000\u0000no\u0001\u0000\u0000\u0000os\u0001\u0000\u0000"+
		"\u0000pn\u0001\u0000\u0000\u0000qs\u0003\u0006\u0003\u0000rb\u0001\u0000"+
		"\u0000\u0000rq\u0001\u0000\u0000\u0000s\u0005\u0001\u0000\u0000\u0000"+
		"tu\u0006\u0003\uffff\uffff\u0000uw\u0005\u0002\u0000\u0000vx\u0005\u0012"+
		"\u0000\u0000wv\u0001\u0000\u0000\u0000wx\u0001\u0000\u0000\u0000xy\u0001"+
		"\u0000\u0000\u0000y{\u0003\u001c\u000e\u0000z|\u0005\u0012\u0000\u0000"+
		"{z\u0001\u0000\u0000\u0000{|\u0001\u0000\u0000\u0000|}\u0001\u0000\u0000"+
		"\u0000}\u007f\u0005\u0003\u0000\u0000~\u0080\u0005\u0012\u0000\u0000\u007f"+
		"~\u0001\u0000\u0000\u0000\u007f\u0080\u0001\u0000\u0000\u0000\u0080\u0081"+
		"\u0001\u0000\u0000\u0000\u0081\u0083\u0003\u0006\u0003\u0000\u0082\u0084"+
		"\u0005\u0012\u0000\u0000\u0083\u0082\u0001\u0000\u0000\u0000\u0083\u0084"+
		"\u0001\u0000\u0000\u0000\u0084\u0085\u0001\u0000\u0000\u0000\u0085\u0087"+
		"\u0005\u0004\u0000\u0000\u0086\u0088\u0005\u0012\u0000\u0000\u0087\u0086"+
		"\u0001\u0000\u0000\u0000\u0087\u0088\u0001\u0000\u0000\u0000\u0088\u0089"+
		"\u0001\u0000\u0000\u0000\u0089\u008a\u0003\u0006\u0003\t\u008a\u00c3\u0001"+
		"\u0000\u0000\u0000\u008b\u008d\u0005$\u0000\u0000\u008c\u008e\u0005\u0012"+
		"\u0000\u0000\u008d\u008c\u0001\u0000\u0000\u0000\u008d\u008e\u0001\u0000"+
		"\u0000\u0000\u008e\u008f\u0001\u0000\u0000\u0000\u008f\u0091\u0003\u0004"+
		"\u0002\u0000\u0090\u0092\u0005\u0012\u0000\u0000\u0091\u0090\u0001\u0000"+
		"\u0000\u0000\u0091\u0092\u0001\u0000\u0000\u0000\u0092\u0093\u0001\u0000"+
		"\u0000\u0000\u0093\u0094\u0005%\u0000\u0000\u0094\u00c3\u0001\u0000\u0000"+
		"\u0000\u0095\u0096\u0005\u0005\u0000\u0000\u0096\u0098\u0005$\u0000\u0000"+
		"\u0097\u0099\u0005\u0012\u0000\u0000\u0098\u0097\u0001\u0000\u0000\u0000"+
		"\u0098\u0099\u0001\u0000\u0000\u0000\u0099\u009a\u0001\u0000\u0000\u0000"+
		"\u009a\u009c\u0003\u0006\u0003\u0000\u009b\u009d\u0005\u0012\u0000\u0000"+
		"\u009c\u009b\u0001\u0000\u0000\u0000\u009c\u009d\u0001\u0000\u0000\u0000"+
		"\u009d\u00b0\u0001\u0000\u0000\u0000\u009e\u00a0\u0005+\u0000\u0000\u009f"+
		"\u00a1\u0005\u0012\u0000\u0000\u00a0\u009f\u0001\u0000\u0000\u0000\u00a0"+
		"\u00a1\u0001\u0000\u0000\u0000\u00a1\u00a2\u0001\u0000\u0000\u0000\u00a2"+
		"\u00a4\u0003\u0006\u0003\u0000\u00a3\u00a5\u0005\u0012\u0000\u0000\u00a4"+
		"\u00a3\u0001\u0000\u0000\u0000\u00a4\u00a5\u0001\u0000\u0000\u0000\u00a5"+
		"\u00ae\u0001\u0000\u0000\u0000\u00a6\u00a8\u0005+\u0000\u0000\u00a7\u00a9"+
		"\u0005\u0012\u0000\u0000\u00a8\u00a7\u0001\u0000\u0000\u0000\u00a8\u00a9"+
		"\u0001\u0000\u0000\u0000\u00a9\u00aa\u0001\u0000\u0000\u0000\u00aa\u00ac"+
		"\u0003\u0006\u0003\u0000\u00ab\u00ad\u0005\u0012\u0000\u0000\u00ac\u00ab"+
		"\u0001\u0000\u0000\u0000\u00ac\u00ad\u0001\u0000\u0000\u0000\u00ad\u00af"+
		"\u0001\u0000\u0000\u0000\u00ae\u00a6\u0001\u0000\u0000\u0000\u00ae\u00af"+
		"\u0001\u0000\u0000\u0000\u00af\u00b1\u0001\u0000\u0000\u0000\u00b0\u009e"+
		"\u0001\u0000\u0000\u0000\u00b0\u00b1\u0001\u0000\u0000\u0000\u00b1\u00b2"+
		"\u0001\u0000\u0000\u0000\u00b2\u00b3\u0005%\u0000\u0000\u00b3\u00c3\u0001"+
		"\u0000\u0000\u0000\u00b4\u00c3\u00034\u001a\u0000\u00b5\u00c3\u0003&\u0013"+
		"\u0000\u00b6\u00c3\u0005\f\u0000\u0000\u00b7\u00b9\u0003.\u0017\u0000"+
		"\u00b8\u00ba\u0005\u0012\u0000\u0000\u00b9\u00b8\u0001\u0000\u0000\u0000"+
		"\u00b9\u00ba\u0001\u0000\u0000\u0000\u00ba\u00bb\u0001\u0000\u0000\u0000"+
		"\u00bb\u00bd\u0003\u001e\u000f\u0000\u00bc\u00be\u0005\u0012\u0000\u0000"+
		"\u00bd\u00bc\u0001\u0000\u0000\u0000\u00bd\u00be\u0001\u0000\u0000\u0000"+
		"\u00be\u00bf\u0001\u0000\u0000\u0000\u00bf\u00c0\u0003\u0006\u0003\u0000"+
		"\u00c0\u00c3\u0001\u0000\u0000\u0000\u00c1\u00c3\u0003.\u0017\u0000\u00c2"+
		"t\u0001\u0000\u0000\u0000\u00c2\u008b\u0001\u0000\u0000\u0000\u00c2\u0095"+
		"\u0001\u0000\u0000\u0000\u00c2\u00b4\u0001\u0000\u0000\u0000\u00c2\u00b5"+
		"\u0001\u0000\u0000\u0000\u00c2\u00b6\u0001\u0000\u0000\u0000\u00c2\u00b7"+
		"\u0001\u0000\u0000\u0000\u00c2\u00c1\u0001\u0000\u0000\u0000\u00c3\u00cb"+
		"\u0001\u0000\u0000\u0000\u00c4\u00c5\n\u0006\u0000\u0000\u00c5\u00c6\u0005"+
		"\u0012\u0000\u0000\u00c6\u00c7\u0005\n\u0000\u0000\u00c7\u00c8\u0005\u0012"+
		"\u0000\u0000\u00c8\u00ca\u0003\u0006\u0003\u0007\u00c9\u00c4\u0001\u0000"+
		"\u0000\u0000\u00ca\u00cd\u0001\u0000\u0000\u0000\u00cb\u00c9\u0001\u0000"+
		"\u0000\u0000\u00cb\u00cc\u0001\u0000\u0000\u0000\u00cc\u0007\u0001\u0000"+
		"\u0000\u0000\u00cd\u00cb\u0001\u0000\u0000\u0000\u00ce\u00d1\u0003\n\u0005"+
		"\u0000\u00cf\u00d1\u0003.\u0017\u0000\u00d0\u00ce\u0001\u0000\u0000\u0000"+
		"\u00d0\u00cf\u0001\u0000\u0000\u0000\u00d1\u00d3\u0001\u0000\u0000\u0000"+
		"\u00d2\u00d4\u0005\u0012\u0000\u0000\u00d3\u00d2\u0001\u0000\u0000\u0000"+
		"\u00d3\u00d4\u0001\u0000\u0000\u0000\u00d4\u00d5\u0001\u0000\u0000\u0000"+
		"\u00d5\u00d7\u0005?\u0000\u0000\u00d6\u00d8\u0005\u0012\u0000\u0000\u00d7"+
		"\u00d6\u0001\u0000\u0000\u0000\u00d7\u00d8\u0001\u0000\u0000\u0000\u00d8"+
		"\u00d9\u0001\u0000\u0000\u0000\u00d9\u00da\u0003\u0004\u0002\u0000\u00da"+
		"\t\u0001\u0000\u0000\u0000\u00db\u00dc\u0005\u0001\u0000\u0000\u00dc\u00dd"+
		"\u0005\u0012\u0000\u0000\u00dd\u00de\u0003*\u0015\u0000\u00de\u000b\u0001"+
		"\u0000\u0000\u0000\u00df\u00e0\u0005&\u0000\u0000\u00e0\u00e6\u0003 \u0010"+
		"\u0000\u00e1\u00e2\u0005\'\u0000\u0000\u00e2\u00e6\u0003\u0004\u0002\u0000"+
		"\u00e3\u00e4\u0005(\u0000\u0000\u00e4\u00e6\u0003$\u0012\u0000\u00e5\u00df"+
		"\u0001\u0000\u0000\u0000\u00e5\u00e1\u0001\u0000\u0000\u0000\u00e5\u00e3"+
		"\u0001\u0000\u0000\u0000\u00e6\r\u0001\u0000\u0000\u0000\u00e7\u00e8\u0005"+
		"\u0007\u0000\u0000\u00e8\u00e9\u0005\u0012\u0000\u0000\u00e9\u00eb\u0003"+
		"\u001c\u000e\u0000\u00ea\u00ec\u0005\u0012\u0000\u0000\u00eb\u00ea\u0001"+
		"\u0000\u0000\u0000\u00eb\u00ec\u0001\u0000\u0000\u0000\u00ec\u00ed\u0001"+
		"\u0000\u0000\u0000\u00ed\u00ee\u0005)\u0000\u0000\u00ee\u00f0\u0003\u0014"+
		"\n\u0000\u00ef\u00f1\u0003\u0010\b\u0000\u00f0\u00ef\u0001\u0000\u0000"+
		"\u0000\u00f0\u00f1\u0001\u0000\u0000\u0000\u00f1\u0113\u0001\u0000\u0000"+
		"\u0000\u00f2\u00f3\u0005\t\u0000\u0000\u00f3\u00f4\u0005\u0012\u0000\u0000"+
		"\u00f4\u00fd\u0003*\u0015\u0000\u00f5\u00f7\u0005\u0012\u0000\u0000\u00f6"+
		"\u00f5\u0001\u0000\u0000\u0000\u00f6\u00f7\u0001\u0000\u0000\u0000\u00f7"+
		"\u00f8\u0001\u0000\u0000\u0000\u00f8\u00fa\u0005+\u0000\u0000\u00f9\u00fb"+
		"\u0005\u0012\u0000\u0000\u00fa\u00f9\u0001\u0000\u0000\u0000\u00fa\u00fb"+
		"\u0001\u0000\u0000\u0000\u00fb\u00fc\u0001\u0000\u0000\u0000\u00fc\u00fe"+
		"\u0003*\u0015\u0000\u00fd\u00f6\u0001\u0000\u0000\u0000\u00fd\u00fe\u0001"+
		"\u0000\u0000\u0000\u00fe\u00ff\u0001\u0000\u0000\u0000\u00ff\u0100\u0005"+
		"\u0012\u0000\u0000\u0100\u0101\u0005\n\u0000\u0000\u0101\u0102\u0005\u0012"+
		"\u0000\u0000\u0102\u0104\u0003\u0018\f\u0000\u0103\u0105\u0005\u0012\u0000"+
		"\u0000\u0104\u0103\u0001\u0000\u0000\u0000\u0104\u0105\u0001\u0000\u0000"+
		"\u0000\u0105\u0106\u0001\u0000\u0000\u0000\u0106\u0107\u0005)\u0000\u0000"+
		"\u0107\u0108\u0003\u0014\n\u0000\u0108\u0113\u0001\u0000\u0000\u0000\u0109"+
		"\u010a\u0005\u000b\u0000\u0000\u010a\u010b\u0005\u0012\u0000\u0000\u010b"+
		"\u010d\u0003\u001c\u000e\u0000\u010c\u010e\u0005\u0012\u0000\u0000\u010d"+
		"\u010c\u0001\u0000\u0000\u0000\u010d\u010e\u0001\u0000\u0000\u0000\u010e"+
		"\u010f\u0001\u0000\u0000\u0000\u010f\u0110\u0005)\u0000\u0000\u0110\u0111"+
		"\u0003\u0014\n\u0000\u0111\u0113\u0001\u0000\u0000\u0000\u0112\u00e7\u0001"+
		"\u0000\u0000\u0000\u0112\u00f2\u0001\u0000\u0000\u0000\u0112\u0109\u0001"+
		"\u0000\u0000\u0000\u0113\u000f\u0001\u0000\u0000\u0000\u0114\u0116\u0005"+
		"\b\u0000\u0000\u0115\u0117\u0005\u0012\u0000\u0000\u0116\u0115\u0001\u0000"+
		"\u0000\u0000\u0116\u0117\u0001\u0000\u0000\u0000\u0117\u0118\u0001\u0000"+
		"\u0000\u0000\u0118\u0119\u0005)\u0000\u0000\u0119\u011a\u0003\u0014\n"+
		"\u0000\u011a\u0011\u0001\u0000\u0000\u0000\u011b\u011c\u0005\u0006\u0000"+
		"\u0000\u011c\u011d\u0005\u0012\u0000\u0000\u011d\u011f\u0003*\u0015\u0000"+
		"\u011e\u0120\u0005\u0012\u0000\u0000\u011f\u011e\u0001\u0000\u0000\u0000"+
		"\u011f\u0120\u0001\u0000\u0000\u0000\u0120\u0121\u0001\u0000\u0000\u0000"+
		"\u0121\u0123\u0005$\u0000\u0000\u0122\u0124\u0003\u001a\r\u0000\u0123"+
		"\u0122\u0001\u0000\u0000\u0000\u0123\u0124\u0001\u0000\u0000\u0000\u0124"+
		"\u0125\u0001\u0000\u0000\u0000\u0125\u0127\u0005%\u0000\u0000\u0126\u0128"+
		"\u0005\u0012\u0000\u0000\u0127\u0126\u0001\u0000\u0000\u0000\u0127\u0128"+
		"\u0001\u0000\u0000\u0000\u0128\u0129\u0001\u0000\u0000\u0000\u0129\u012a"+
		"\u0005)\u0000\u0000\u012a\u012b\u0003\u0014\n\u0000\u012b\u0013\u0001"+
		"\u0000\u0000\u0000\u012c\u0131\u0005M\u0000\u0000\u012d\u012f\u0003\u0016"+
		"\u000b\u0000\u012e\u0130\u0005\u0011\u0000\u0000\u012f\u012e\u0001\u0000"+
		"\u0000\u0000\u012f\u0130\u0001\u0000\u0000\u0000\u0130\u0132\u0001\u0000"+
		"\u0000\u0000\u0131\u012d\u0001\u0000\u0000\u0000\u0132\u0133\u0001\u0000"+
		"\u0000\u0000\u0133\u0131\u0001\u0000\u0000\u0000\u0133\u0134\u0001\u0000"+
		"\u0000\u0000\u0134\u0135\u0001\u0000\u0000\u0000\u0135\u0136\u0005N\u0000"+
		"\u0000\u0136\u0015\u0001\u0000\u0000\u0000\u0137\u013e\u0005\u000f\u0000"+
		"\u0000\u0138\u013e\u0005\u0010\u0000\u0000\u0139\u013a\u0005\u000e\u0000"+
		"\u0000\u013a\u013b\u0005\u0012\u0000\u0000\u013b\u013e\u0003\u0004\u0002"+
		"\u0000\u013c\u013e\u0003\u0002\u0001\u0000\u013d\u0137\u0001\u0000\u0000"+
		"\u0000\u013d\u0138\u0001\u0000\u0000\u0000\u013d\u0139\u0001\u0000\u0000"+
		"\u0000\u013d\u013c\u0001\u0000\u0000\u0000\u013e\u0017\u0001\u0000\u0000"+
		"\u0000\u013f\u0140\u0003\u0004\u0002\u0000\u0140\u0019\u0001\u0000\u0000"+
		"\u0000\u0141\u014c\u0003*\u0015\u0000\u0142\u0144\u0005\u0012\u0000\u0000"+
		"\u0143\u0142\u0001\u0000\u0000\u0000\u0143\u0144\u0001\u0000\u0000\u0000"+
		"\u0144\u0145\u0001\u0000\u0000\u0000\u0145\u0147\u0005+\u0000\u0000\u0146"+
		"\u0148\u0005\u0012\u0000\u0000\u0147\u0146\u0001\u0000\u0000\u0000\u0147"+
		"\u0148\u0001\u0000\u0000\u0000\u0148\u0149\u0001\u0000\u0000\u0000\u0149"+
		"\u014b\u0003*\u0015\u0000\u014a\u0143\u0001\u0000\u0000\u0000\u014b\u014e"+
		"\u0001\u0000\u0000\u0000\u014c\u014a\u0001\u0000\u0000\u0000\u014c\u014d"+
		"\u0001\u0000\u0000\u0000\u014d\u001b\u0001\u0000\u0000\u0000\u014e\u014c"+
		"\u0001\u0000\u0000\u0000\u014f\u0150\u0003\u0004\u0002\u0000\u0150\u001d"+
		"\u0001\u0000\u0000\u0000\u0151\u0165\u00059\u0000\u0000\u0152\u0165\u0005"+
		"L\u0000\u0000\u0153\u0165\u00058\u0000\u0000\u0154\u0165\u0005:\u0000"+
		"\u0000\u0155\u0165\u00057\u0000\u0000\u0156\u0165\u0005>\u0000\u0000\u0157"+
		"\u0165\u0005@\u0000\u0000\u0158\u0165\u0005A\u0000\u0000\u0159\u0165\u0005"+
		"C\u0000\u0000\u015a\u0165\u0005B\u0000\u0000\u015b\u0165\u0005D\u0000"+
		"\u0000\u015c\u0165\u0005E\u0000\u0000\u015d\u0165\u0005F\u0000\u0000\u015e"+
		"\u015f\u0005G\u0000\u0000\u015f\u0165\u0005;\u0000\u0000\u0160\u0165\u0005"+
		"<\u0000\u0000\u0161\u0165\u0005=\u0000\u0000\u0162\u0165\u0005\'\u0000"+
		"\u0000\u0163\u0165\u00050\u0000\u0000\u0164\u0151\u0001\u0000\u0000\u0000"+
		"\u0164\u0152\u0001\u0000\u0000\u0000\u0164\u0153\u0001\u0000\u0000\u0000"+
		"\u0164\u0154\u0001\u0000\u0000\u0000\u0164\u0155\u0001\u0000\u0000\u0000"+
		"\u0164\u0156\u0001\u0000\u0000\u0000\u0164\u0157\u0001\u0000\u0000\u0000"+
		"\u0164\u0158\u0001\u0000\u0000\u0000\u0164\u0159\u0001\u0000\u0000\u0000"+
		"\u0164\u015a\u0001\u0000\u0000\u0000\u0164\u015b\u0001\u0000\u0000\u0000"+
		"\u0164\u015c\u0001\u0000\u0000\u0000\u0164\u015d\u0001\u0000\u0000\u0000"+
		"\u0164\u015e\u0001\u0000\u0000\u0000\u0164\u0160\u0001\u0000\u0000\u0000"+
		"\u0164\u0161\u0001\u0000\u0000\u0000\u0164\u0162\u0001\u0000\u0000\u0000"+
		"\u0164\u0163\u0001\u0000\u0000\u0000\u0165\u001f\u0001\u0000\u0000\u0000"+
		"\u0166\u0168\u0003*\u0015\u0000\u0167\u0169\u0005\u0012\u0000\u0000\u0168"+
		"\u0167\u0001\u0000\u0000\u0000\u0168\u0169\u0001\u0000\u0000\u0000\u0169"+
		"\u016a\u0001\u0000\u0000\u0000\u016a\u016c\u0005$\u0000\u0000\u016b\u016d"+
		"\u0005\u0012\u0000\u0000\u016c\u016b\u0001\u0000\u0000\u0000\u016c\u016d"+
		"\u0001\u0000\u0000\u0000\u016d\u0171\u0001\u0000\u0000\u0000\u016e\u0170"+
		"\u0003\"\u0011\u0000\u016f\u016e\u0001\u0000\u0000\u0000\u0170\u0173\u0001"+
		"\u0000\u0000\u0000\u0171\u016f\u0001\u0000\u0000\u0000\u0171\u0172\u0001"+
		"\u0000\u0000\u0000\u0172\u0174\u0001\u0000\u0000\u0000\u0173\u0171\u0001"+
		"\u0000\u0000\u0000\u0174\u0175\u0005%\u0000\u0000\u0175!\u0001\u0000\u0000"+
		"\u0000\u0176\u017e\u0003&\u0013\u0000\u0177\u017e\u00034\u001a\u0000\u0178"+
		"\u017e\u00030\u0018\u0000\u0179\u017a\u0005$\u0000\u0000\u017a\u017b\u0003"+
		"\"\u0011\u0000\u017b\u017c\u0005%\u0000\u0000\u017c\u017e\u0001\u0000"+
		"\u0000\u0000\u017d\u0176\u0001\u0000\u0000\u0000\u017d\u0177\u0001\u0000"+
		"\u0000\u0000\u017d\u0178\u0001\u0000\u0000\u0000\u017d\u0179\u0001\u0000"+
		"\u0000\u0000\u017e\u017f\u0001\u0000\u0000\u0000\u017f\u017d\u0001\u0000"+
		"\u0000\u0000\u017f\u0180\u0001\u0000\u0000\u0000\u0180#\u0001\u0000\u0000"+
		"\u0000\u0181\u0189\u0003&\u0013\u0000\u0182\u0189\u00034\u001a\u0000\u0183"+
		"\u0189\u00030\u0018\u0000\u0184\u0185\u0005$\u0000\u0000\u0185\u0186\u0003"+
		"$\u0012\u0000\u0186\u0187\u0005%\u0000\u0000\u0187\u0189\u0001\u0000\u0000"+
		"\u0000\u0188\u0181\u0001\u0000\u0000\u0000\u0188\u0182\u0001\u0000\u0000"+
		"\u0000\u0188\u0183\u0001\u0000\u0000\u0000\u0188\u0184\u0001\u0000\u0000"+
		"\u0000\u0189\u018c\u0001\u0000\u0000\u0000\u018a\u0188\u0001\u0000\u0000"+
		"\u0000\u018a\u018b\u0001\u0000\u0000\u0000\u018b%\u0001\u0000\u0000\u0000"+
		"\u018c\u018a\u0001\u0000\u0000\u0000\u018d\u018e\u0007\u0001\u0000\u0000"+
		"\u018e\u018f\u0005/\u0000\u0000\u018f\u0191\u0003*\u0015\u0000\u0190\u0192"+
		"\u0005&\u0000\u0000\u0191\u0190\u0001\u0000\u0000\u0000\u0191\u0192\u0001"+
		"\u0000\u0000\u0000\u0192\u01a9\u0001\u0000\u0000\u0000\u0193\u01a9\u0005"+
		"\u001c\u0000\u0000\u0194\u0195\u0005\u001b\u0000\u0000\u0195\u0197\u0005"+
		"1\u0000\u0000\u0196\u0198\u0005\u0012\u0000\u0000\u0197\u0196\u0001\u0000"+
		"\u0000\u0000\u0197\u0198\u0001\u0000\u0000\u0000\u0198\u0199\u0001\u0000"+
		"\u0000\u0000\u0199\u01a2\u0003(\u0014\u0000\u019a\u019c\u0005\u0012\u0000"+
		"\u0000\u019b\u019a\u0001\u0000\u0000\u0000\u019b\u019c\u0001\u0000\u0000"+
		"\u0000\u019c\u019d\u0001\u0000\u0000\u0000\u019d\u019f\u0005#\u0000\u0000"+
		"\u019e\u01a0\u0005\u0012\u0000\u0000\u019f\u019e\u0001\u0000\u0000\u0000"+
		"\u019f\u01a0\u0001\u0000\u0000\u0000\u01a0\u01a1\u0001\u0000\u0000\u0000"+
		"\u01a1\u01a3\u0003(\u0014\u0000\u01a2\u019b\u0001\u0000\u0000\u0000\u01a2"+
		"\u01a3\u0001\u0000\u0000\u0000\u01a3\u01a4\u0001\u0000\u0000\u0000\u01a4"+
		"\u01a6\u00052\u0000\u0000\u01a5\u01a7\u0005&\u0000\u0000\u01a6\u01a5\u0001"+
		"\u0000\u0000\u0000\u01a6\u01a7\u0001\u0000\u0000\u0000\u01a7\u01a9\u0001"+
		"\u0000\u0000\u0000\u01a8\u018d\u0001\u0000\u0000\u0000\u01a8\u0193\u0001"+
		"\u0000\u0000\u0000\u01a8\u0194\u0001\u0000\u0000\u0000\u01a9\'\u0001\u0000"+
		"\u0000\u0000\u01aa\u01ac\u0005L\u0000\u0000\u01ab\u01aa\u0001\u0000\u0000"+
		"\u0000\u01ab\u01ac\u0001\u0000\u0000\u0000\u01ac\u01ad\u0001\u0000\u0000"+
		"\u0000\u01ad\u01ae\u0003\u0004\u0002\u0000\u01ae)\u0001\u0000\u0000\u0000"+
		"\u01af\u01b5\u0005\u0016\u0000\u0000\u01b0\u01b5\u0005K\u0000\u0000\u01b1"+
		"\u01b2\u00032\u0019\u0000\u01b2\u01b3\u0005K\u0000\u0000\u01b3\u01b5\u0001"+
		"\u0000\u0000\u0000\u01b4\u01af\u0001\u0000\u0000\u0000\u01b4\u01b0\u0001"+
		"\u0000\u0000\u0000\u01b4\u01b1\u0001\u0000\u0000\u0000\u01b5\u01bc\u0001"+
		"\u0000\u0000\u0000\u01b6\u01bb\u0005\u0016\u0000\u0000\u01b7\u01bb\u0005"+
		"\u0014\u0000\u0000\u01b8\u01bb\u0005K\u0000\u0000\u01b9\u01bb\u00032\u0019"+
		"\u0000\u01ba\u01b6\u0001\u0000\u0000\u0000\u01ba\u01b7\u0001\u0000\u0000"+
		"\u0000\u01ba\u01b8\u0001\u0000\u0000\u0000\u01ba\u01b9\u0001\u0000\u0000"+
		"\u0000\u01bb\u01be\u0001\u0000\u0000\u0000\u01bc\u01ba\u0001\u0000\u0000"+
		"\u0000\u01bc\u01bd\u0001\u0000\u0000\u0000\u01bd+\u0001\u0000\u0000\u0000"+
		"\u01be\u01bc\u0001\u0000\u0000\u0000\u01bf\u01c0\u0007\u0002\u0000\u0000"+
		"\u01c0-\u0001\u0000\u0000\u0000\u01c1\u01c2\u0006\u0017\uffff\uffff\u0000"+
		"\u01c2\u01c4\u0003*\u0015\u0000\u01c3\u01c5\u0005&\u0000\u0000\u01c4\u01c3"+
		"\u0001\u0000\u0000\u0000\u01c4\u01c5\u0001\u0000\u0000\u0000\u01c5\u020e"+
		"\u0001\u0000\u0000\u0000\u01c6\u01c8\u0005L\u0000\u0000\u01c7\u01c6\u0001"+
		"\u0000\u0000\u0000\u01c7\u01c8\u0001\u0000\u0000\u0000\u01c8\u01c9\u0001"+
		"\u0000\u0000\u0000\u01c9\u020e\u0003,\u0016\u0000\u01ca\u020e\u0005\f"+
		"\u0000\u0000\u01cb\u020e\u0003&\u0013\u0000\u01cc\u01ce\u00051\u0000\u0000"+
		"\u01cd\u01cf\u0005\u0012\u0000\u0000\u01ce\u01cd\u0001\u0000\u0000\u0000"+
		"\u01ce\u01cf\u0001\u0000\u0000\u0000\u01cf\u01d1\u0001\u0000\u0000\u0000"+
		"\u01d0\u01d2\u0003.\u0017\u0000\u01d1\u01d0\u0001\u0000\u0000\u0000\u01d1"+
		"\u01d2\u0001\u0000\u0000\u0000\u01d2\u01dd\u0001\u0000\u0000\u0000\u01d3"+
		"\u01d5\u0005\u0012\u0000\u0000\u01d4\u01d3\u0001\u0000\u0000\u0000\u01d4"+
		"\u01d5\u0001\u0000\u0000\u0000\u01d5\u01d6\u0001\u0000\u0000\u0000\u01d6"+
		"\u01d8\u0005+\u0000\u0000\u01d7\u01d9\u0005\u0012\u0000\u0000\u01d8\u01d7"+
		"\u0001\u0000\u0000\u0000\u01d8\u01d9\u0001\u0000\u0000\u0000\u01d9\u01da"+
		"\u0001\u0000\u0000\u0000\u01da\u01dc\u0003.\u0017\u0000\u01db\u01d4\u0001"+
		"\u0000\u0000\u0000\u01dc\u01df\u0001\u0000\u0000\u0000\u01dd\u01db\u0001"+
		"\u0000\u0000\u0000\u01dd\u01de\u0001\u0000\u0000\u0000\u01de\u01e1\u0001"+
		"\u0000\u0000\u0000\u01df\u01dd\u0001\u0000\u0000\u0000\u01e0\u01e2\u0005"+
		"\u0012\u0000\u0000\u01e1\u01e0\u0001\u0000\u0000\u0000\u01e1\u01e2\u0001"+
		"\u0000\u0000\u0000\u01e2\u01e3\u0001\u0000\u0000\u0000\u01e3\u020e\u0005"+
		"2\u0000\u0000\u01e4\u01e6\u00053\u0000\u0000\u01e5\u01e7\u0005\u0012\u0000"+
		"\u0000\u01e6\u01e5\u0001\u0000\u0000\u0000\u01e6\u01e7\u0001\u0000\u0000"+
		"\u0000\u01e7\u0204\u0001\u0000\u0000\u0000\u01e8\u01ea\u0005\u001d\u0000"+
		"\u0000\u01e9\u01eb\u0005\u0012\u0000\u0000\u01ea\u01e9\u0001\u0000\u0000"+
		"\u0000\u01ea\u01eb\u0001\u0000\u0000\u0000\u01eb\u01ec\u0001\u0000\u0000"+
		"\u0000\u01ec\u01ee\u0005)\u0000\u0000\u01ed\u01ef\u0005\u0012\u0000\u0000"+
		"\u01ee\u01ed\u0001\u0000\u0000\u0000\u01ee\u01ef\u0001\u0000\u0000\u0000"+
		"\u01ef\u01f0\u0001\u0000\u0000\u0000\u01f0\u01f2\u0003.\u0017\u0000\u01f1"+
		"\u01f3\u0005\u0012\u0000\u0000\u01f2\u01f1\u0001\u0000\u0000\u0000\u01f2"+
		"\u01f3\u0001\u0000\u0000\u0000\u01f3\u01f4\u0001\u0000\u0000\u0000\u01f4"+
		"\u01f6\u0005+\u0000\u0000\u01f5\u01f7\u0005\u0012\u0000\u0000\u01f6\u01f5"+
		"\u0001\u0000\u0000\u0000\u01f6\u01f7\u0001\u0000\u0000\u0000\u01f7\u01f8"+
		"\u0001\u0000\u0000\u0000\u01f8\u01fa\u0005\u001d\u0000\u0000\u01f9\u01fb"+
		"\u0005\u0012\u0000\u0000\u01fa\u01f9\u0001\u0000\u0000\u0000\u01fa\u01fb"+
		"\u0001\u0000\u0000\u0000\u01fb\u01fc\u0001\u0000\u0000\u0000\u01fc\u01fe"+
		"\u0005)\u0000\u0000\u01fd\u01ff\u0005\u0012\u0000\u0000\u01fe\u01fd\u0001"+
		"\u0000\u0000\u0000\u01fe\u01ff\u0001\u0000\u0000\u0000\u01ff\u0200\u0001"+
		"\u0000\u0000\u0000\u0200\u0201\u0003.\u0017\u0000\u0201\u0203\u0001\u0000"+
		"\u0000\u0000\u0202\u01e8\u0001\u0000\u0000\u0000\u0203\u0206\u0001\u0000"+
		"\u0000\u0000\u0204\u0202\u0001\u0000\u0000\u0000\u0204\u0205\u0001\u0000"+
		"\u0000\u0000\u0205\u0208\u0001\u0000\u0000\u0000\u0206\u0204\u0001\u0000"+
		"\u0000\u0000\u0207\u0209\u0005\u0012\u0000\u0000\u0208\u0207\u0001\u0000"+
		"\u0000\u0000\u0208\u0209\u0001\u0000\u0000\u0000\u0209\u020a\u0001\u0000"+
		"\u0000\u0000\u020a\u020e\u00054\u0000\u0000\u020b\u020e\u0005\u001d\u0000"+
		"\u0000\u020c\u020e\u0005\u001e\u0000\u0000\u020d\u01c1\u0001\u0000\u0000"+
		"\u0000\u020d\u01c7\u0001\u0000\u0000\u0000\u020d\u01ca\u0001\u0000\u0000"+
		"\u0000\u020d\u01cb\u0001\u0000\u0000\u0000\u020d\u01cc\u0001\u0000\u0000"+
		"\u0000\u020d\u01e4\u0001\u0000\u0000\u0000\u020d\u020b\u0001\u0000\u0000"+
		"\u0000\u020d\u020c\u0001\u0000\u0000\u0000\u020e\u0247\u0001\u0000\u0000"+
		"\u0000\u020f\u0210\n\b\u0000\u0000\u0210\u0211\u0005/\u0000\u0000\u0211"+
		"\u0246\u0003*\u0015\u0000\u0212\u0213\n\u0007\u0000\u0000\u0213\u0215"+
		"\u00051\u0000\u0000\u0214\u0216\u0005\u0012\u0000\u0000\u0215\u0214\u0001"+
		"\u0000\u0000\u0000\u0215\u0216\u0001\u0000\u0000\u0000\u0216\u0217\u0001"+
		"\u0000\u0000\u0000\u0217\u0219\u0003(\u0014\u0000\u0218\u021a\u0005\u0012"+
		"\u0000\u0000\u0219\u0218\u0001\u0000\u0000\u0000\u0219\u021a\u0001\u0000"+
		"\u0000\u0000\u021a\u021b\u0001\u0000\u0000\u0000\u021b\u021c\u00052\u0000"+
		"\u0000\u021c\u0246\u0001\u0000\u0000\u0000\u021d\u021e\n\u0006\u0000\u0000"+
		"\u021e\u0220\u00051\u0000\u0000\u021f\u0221\u0005\u0012\u0000\u0000\u0220"+
		"\u021f\u0001\u0000\u0000\u0000\u0220\u0221\u0001\u0000\u0000\u0000\u0221"+
		"\u0222\u0001\u0000\u0000\u0000\u0222\u0224\u0003(\u0014\u0000\u0223\u0225"+
		"\u0005\u0012\u0000\u0000\u0224\u0223\u0001\u0000\u0000\u0000\u0224\u0225"+
		"\u0001\u0000\u0000\u0000\u0225\u0226\u0001\u0000\u0000\u0000\u0226\u0228"+
		"\u0005)\u0000\u0000\u0227\u0229\u0005\u0012\u0000\u0000\u0228\u0227\u0001"+
		"\u0000\u0000\u0000\u0228\u0229\u0001\u0000\u0000\u0000\u0229\u022b\u0001"+
		"\u0000\u0000\u0000\u022a\u022c\u0003(\u0014\u0000\u022b\u022a\u0001\u0000"+
		"\u0000\u0000\u022b\u022c\u0001\u0000\u0000\u0000\u022c\u022e\u0001\u0000"+
		"\u0000\u0000\u022d\u022f\u0005\u0012\u0000\u0000\u022e\u022d\u0001\u0000"+
		"\u0000\u0000\u022e\u022f\u0001\u0000\u0000\u0000\u022f\u0230\u0001\u0000"+
		"\u0000\u0000\u0230\u0231\u00052\u0000\u0000\u0231\u0246\u0001\u0000\u0000"+
		"\u0000\u0232\u0233\n\u0005\u0000\u0000\u0233\u0235\u00051\u0000\u0000"+
		"\u0234\u0236\u0005\u0012\u0000\u0000\u0235\u0234\u0001\u0000\u0000\u0000"+
		"\u0235\u0236\u0001\u0000\u0000\u0000\u0236\u0237\u0001\u0000\u0000\u0000"+
		"\u0237\u0239\u0003(\u0014\u0000\u0238\u023a\u0005\u0012\u0000\u0000\u0239"+
		"\u0238\u0001\u0000\u0000\u0000\u0239\u023a\u0001\u0000\u0000\u0000\u023a"+
		"\u023b\u0001\u0000\u0000\u0000\u023b\u023d\u0005#\u0000\u0000\u023c\u023e"+
		"\u0005\u0012\u0000\u0000\u023d\u023c\u0001\u0000\u0000\u0000\u023d\u023e"+
		"\u0001\u0000\u0000\u0000\u023e\u023f\u0001\u0000\u0000\u0000\u023f\u0241"+
		"\u0003(\u0014\u0000\u0240\u0242\u0005\u0012\u0000\u0000\u0241\u0240\u0001"+
		"\u0000\u0000\u0000\u0241\u0242\u0001\u0000\u0000\u0000\u0242\u0243\u0001"+
		"\u0000\u0000\u0000\u0243\u0244\u00052\u0000\u0000\u0244\u0246\u0001\u0000"+
		"\u0000\u0000\u0245\u020f\u0001\u0000\u0000\u0000\u0245\u0212\u0001\u0000"+
		"\u0000\u0000\u0245\u021d\u0001\u0000\u0000\u0000\u0245\u0232\u0001\u0000"+
		"\u0000\u0000\u0246\u0249\u0001\u0000\u0000\u0000\u0247\u0245\u0001\u0000"+
		"\u0000\u0000\u0247\u0248\u0001\u0000\u0000\u0000\u0248/\u0001\u0000\u0000"+
		"\u0000\u0249\u0247\u0001\u0000\u0000\u0000\u024a\u0256\u0005\u0016\u0000"+
		"\u0000\u024b\u0256\u0005\u0014\u0000\u0000\u024c\u0256\u0003<\u001e\u0000"+
		"\u024d\u0256\u0005\u001d\u0000\u0000\u024e\u0256\u0005\u001e\u0000\u0000"+
		"\u024f\u0256\u0005\u0012\u0000\u0000\u0250\u0251\u0005$\u0000\u0000\u0251"+
		"\u0252\u00030\u0018\u0000\u0252\u0253\u0005%\u0000\u0000\u0253\u0256\u0001"+
		"\u0000\u0000\u0000\u0254\u0256\u00032\u0019\u0000\u0255\u024a\u0001\u0000"+
		"\u0000\u0000\u0255\u024b\u0001\u0000\u0000\u0000\u0255\u024c\u0001\u0000"+
		"\u0000\u0000\u0255\u024d\u0001\u0000\u0000\u0000\u0255\u024e\u0001\u0000"+
		"\u0000\u0000\u0255\u024f\u0001\u0000\u0000\u0000\u0255\u0250\u0001\u0000"+
		"\u0000\u0000\u0255\u0254\u0001\u0000\u0000\u0000\u02561\u0001\u0000\u0000"+
		"\u0000\u0257\u0258\u0007\u0003\u0000\u0000\u02583\u0001\u0000\u0000\u0000"+
		"\u0259\u025d\u00036\u001b\u0000\u025a\u025d\u00038\u001c\u0000\u025b\u025d"+
		"\u0003:\u001d\u0000\u025c\u0259\u0001\u0000\u0000\u0000\u025c\u025a\u0001"+
		"\u0000\u0000\u0000\u025c\u025b\u0001\u0000\u0000\u0000\u025d5\u0001\u0000"+
		"\u0000\u0000\u025e\u025f\u0005\'\u0000\u0000\u025f\u0260\u0005$\u0000"+
		"\u0000\u0260\u0261\u0003\u0004\u0002\u0000\u0261\u0262\u0005%\u0000\u0000"+
		"\u02627\u0001\u0000\u0000\u0000\u0263\u0264\u0005(\u0000\u0000\u0264\u0265"+
		"\u0005$\u0000\u0000\u0265\u0266\u0003$\u0012\u0000\u0266\u0267\u0005%"+
		"\u0000\u0000\u02679\u0001\u0000\u0000\u0000\u0268\u0269\u0005&\u0000\u0000"+
		"\u0269\u026a\u0005$\u0000\u0000\u026a\u026b\u0003\"\u0011\u0000\u026b"+
		"\u026c\u0005%\u0000\u0000\u026c;\u0001\u0000\u0000\u0000\u026d\u026e\u0007"+
		"\u0004\u0000\u0000\u026e=\u0001\u0000\u0000\u0000fAGIL]binrw{\u007f\u0083"+
		"\u0087\u008d\u0091\u0098\u009c\u00a0\u00a4\u00a8\u00ac\u00ae\u00b0\u00b9"+
		"\u00bd\u00c2\u00cb\u00d0\u00d3\u00d7\u00e5\u00eb\u00f0\u00f6\u00fa\u00fd"+
		"\u0104\u010d\u0112\u0116\u011f\u0123\u0127\u012f\u0133\u013d\u0143\u0147"+
		"\u014c\u0164\u0168\u016c\u0171\u017d\u017f\u0188\u018a\u0191\u0197\u019b"+
		"\u019f\u01a2\u01a6\u01a8\u01ab\u01b4\u01ba\u01bc\u01c4\u01c7\u01ce\u01d1"+
		"\u01d4\u01d8\u01dd\u01e1\u01e6\u01ea\u01ee\u01f2\u01f6\u01fa\u01fe\u0204"+
		"\u0208\u020d\u0215\u0219\u0220\u0224\u0228\u022b\u022e\u0235\u0239\u023d"+
		"\u0241\u0245\u0247\u0255\u025c";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}