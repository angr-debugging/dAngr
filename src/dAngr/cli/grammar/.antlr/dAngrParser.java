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
		IN=10, NOT_IN=11, NOT=12, WHILE=13, BOOL=14, HELP=15, RETURN=16, BREAK=17, 
		CONTINUE=18, NEWLINE=19, WS=20, HEX_NUMBERS=21, NUMBERS=22, NUMBER=23, 
		LETTERS=24, LETTER=25, SYM_DB=26, REG_DB=27, VARS_DB=28, MEM_DB=29, STATE=30, 
		STRING=31, BINARY_STRING=32, ESCAPED_QUOTE=33, ESCAPED_SINGLE_QUOTE=34, 
		SESC_SEQ=35, ESC_SEQ=36, ARROW=37, LPAREN=38, RPAREN=39, BANG=40, AMP=41, 
		DOLLAR=42, COLON=43, SCOLON=44, COMMA=45, QUOTE=46, SQUOTE=47, AT=48, 
		DOT=49, BAR=50, BRA=51, KET=52, BRACE=53, KETCE=54, XOR=55, HASH=56, PERC=57, 
		MUL=58, ADD=59, DIV=60, FLOORDIV=61, LSHIFT=62, RSHIFT=63, POW=64, ASSIGN=65, 
		EQ=66, NEQ=67, LT=68, GT=69, LE=70, GE=71, AND=72, OR=73, QMARK=74, TILDE=75, 
		TICK=76, UNDERSCORE=77, DASH=78, INDENT=79, DEDENT=80, HAT=81;
	public static final int
		RULE_script = 0, RULE_statement = 1, RULE_expression = 2, RULE_expression_part = 3, 
		RULE_assignment = 4, RULE_static_var = 5, RULE_ext_command = 6, RULE_control_flow = 7, 
		RULE_else_ = 8, RULE_function_def = 9, RULE_body = 10, RULE_fstatement = 11, 
		RULE_iterable = 12, RULE_parameters = 13, RULE_condition = 14, RULE_operation = 15, 
		RULE_py_basic_content = 16, RULE_py_content = 17, RULE_bash_content = 18, 
		RULE_reference = 19, RULE_index = 20, RULE_identifier = 21, RULE_numeric = 22, 
		RULE_object = 23, RULE_anything = 24, RULE_anything_no = 25, RULE_special_words = 26, 
		RULE_range = 27, RULE_dangr_range = 28, RULE_bash_range = 29, RULE_python_range = 30, 
		RULE_symbol = 31;
	private static String[] makeRuleNames() {
		return new String[] {
			"script", "statement", "expression", "expression_part", "assignment", 
			"static_var", "ext_command", "control_flow", "else_", "function_def", 
			"body", "fstatement", "iterable", "parameters", "condition", "operation", 
			"py_basic_content", "py_content", "bash_content", "reference", "index", 
			"identifier", "numeric", "object", "anything", "anything_no", "special_words", 
			"range", "dangr_range", "bash_range", "python_range", "symbol"
		};
	}
	public static final String[] ruleNames = makeRuleNames();

	private static String[] makeLiteralNames() {
		return new String[] {
			null, "'static'", "'IIF'", "'THEN'", "'ELSE'", "'range'", "'def'", "'if'", 
			"'else'", "'for'", "'in'", "'not in'", "'not'", "'while'", null, "'help'", 
			"'return'", "'break'", "'continue'", null, null, null, null, null, null, 
			null, "'&sym'", "'&reg'", "'&vars'", "'&mem'", "'&state'", null, null, 
			null, null, null, null, "'->'", "'('", "')'", "'!'", "'&'", "'$'", "':'", 
			"';'", "','", "'\"'", "'''", "'@'", "'.'", "'|'", "'['", "']'", "'{'", 
			"'}'", "'^'", "'#'", "'%'", "'*'", "'+'", "'/'", "'//'", "'<<'", "'>>'", 
			"'**'", "'='", "'=='", "'!='", "'<'", "'>'", "'<='", "'>='", "'&&'", 
			"'||'", "'?'", "'~'", "'`'", "'_'", "'-'"
		};
	}
	private static final String[] _LITERAL_NAMES = makeLiteralNames();
	private static String[] makeSymbolicNames() {
		return new String[] {
			null, "STATIC", "CIF", "CTHEN", "CELSE", "RANGE", "DEF", "IF", "ELSE", 
			"FOR", "IN", "NOT_IN", "NOT", "WHILE", "BOOL", "HELP", "RETURN", "BREAK", 
			"CONTINUE", "NEWLINE", "WS", "HEX_NUMBERS", "NUMBERS", "NUMBER", "LETTERS", 
			"LETTER", "SYM_DB", "REG_DB", "VARS_DB", "MEM_DB", "STATE", "STRING", 
			"BINARY_STRING", "ESCAPED_QUOTE", "ESCAPED_SINGLE_QUOTE", "SESC_SEQ", 
			"ESC_SEQ", "ARROW", "LPAREN", "RPAREN", "BANG", "AMP", "DOLLAR", "COLON", 
			"SCOLON", "COMMA", "QUOTE", "SQUOTE", "AT", "DOT", "BAR", "BRA", "KET", 
			"BRACE", "KETCE", "XOR", "HASH", "PERC", "MUL", "ADD", "DIV", "FLOORDIV", 
			"LSHIFT", "RSHIFT", "POW", "ASSIGN", "EQ", "NEQ", "LT", "GT", "LE", "GE", 
			"AND", "OR", "QMARK", "TILDE", "TICK", "UNDERSCORE", "DASH", "INDENT", 
			"DEDENT", "HAT"
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
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
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
		public List<TerminalNode> HASH() { return getTokens(dAngrParser.HASH); }
		public TerminalNode HASH(int i) {
			return getToken(dAngrParser.HASH, i);
		}
		public List<Anything_noContext> anything_no() {
			return getRuleContexts(Anything_noContext.class);
		}
		public Anything_noContext anything_no(int i) {
			return getRuleContext(Anything_noContext.class,i);
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
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(91);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,5,_ctx) ) {
			case 1:
				{
				setState(64);
				_la = _input.LA(1);
				if ( !(_la==HELP || _la==QMARK) ) {
				_errHandler.recoverInline(this);
				}
				else {
					if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
					_errHandler.reportMatch(this);
					consume();
				}
				setState(67);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(65);
					match(WS);
					setState(66);
					identifier();
					}
				}

				setState(69);
				match(NEWLINE);
				}
				break;
			case 2:
				{
				setState(82);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while ((((_la) & ~0x3f) == 0 && ((1L << _la) & 83324573112598526L) != 0) || _la==UNDERSCORE || _la==DASH) {
					{
					setState(80);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,2,_ctx) ) {
					case 1:
						{
						setState(70);
						match(NEWLINE);
						}
						break;
					case 2:
						{
						setState(71);
						statement();
						}
						break;
					case 3:
						{
						setState(72);
						function_def();
						}
						break;
					case 4:
						{
						setState(73);
						match(HASH);
						setState(77);
						_errHandler.sync(this);
						_alt = getInterpreter().adaptivePredict(_input,1,_ctx);
						while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
							if ( _alt==1 ) {
								{
								{
								setState(74);
								anything_no();
								}
								} 
							}
							setState(79);
							_errHandler.sync(this);
							_alt = getInterpreter().adaptivePredict(_input,1,_ctx);
						}
						}
						break;
					}
					}
					setState(84);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(88);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==WS) {
					{
					{
					setState(85);
					match(WS);
					}
					}
					setState(90);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				}
				break;
			}
			setState(93);
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
		public List<TerminalNode> WS() { return getTokens(dAngrParser.WS); }
		public TerminalNode WS(int i) {
			return getToken(dAngrParser.WS, i);
		}
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
		int _la;
		try {
			setState(132);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,10,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(95);
				control_flow();
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(96);
				assignment();
				setState(100);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==WS) {
					{
					{
					setState(97);
					match(WS);
					}
					}
					setState(102);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(103);
				match(NEWLINE);
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				setState(105);
				expression();
				setState(109);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==WS) {
					{
					{
					setState(106);
					match(WS);
					}
					}
					setState(111);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(112);
				match(NEWLINE);
				}
				break;
			case 4:
				enterOuterAlt(_localctx, 4);
				{
				setState(114);
				static_var();
				setState(118);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==WS) {
					{
					{
					setState(115);
					match(WS);
					}
					}
					setState(120);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(121);
				match(NEWLINE);
				}
				break;
			case 5:
				enterOuterAlt(_localctx, 5);
				{
				setState(123);
				ext_command();
				setState(127);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==WS) {
					{
					{
					setState(124);
					match(WS);
					}
					}
					setState(129);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(130);
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
			setState(153);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,14,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(137);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,11,_ctx) ) {
				case 1:
					{
					setState(134);
					identifier();
					setState(135);
					match(DOT);
					}
					break;
				}
				setState(139);
				identifier();
				setState(149);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,13,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(140);
						match(WS);
						setState(144);
						_errHandler.sync(this);
						switch ( getInterpreter().adaptivePredict(_input,12,_ctx) ) {
						case 1:
							{
							setState(141);
							identifier();
							setState(142);
							match(ASSIGN);
							}
							break;
						}
						setState(146);
						expression_part(0);
						}
						} 
					}
					setState(151);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,13,_ctx);
				}
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(152);
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
		public TerminalNode NOT_IN() { return getToken(dAngrParser.NOT_IN, 0); }
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
	public static class ExpressionNotContext extends Expression_partContext {
		public TerminalNode NOT() { return getToken(dAngrParser.NOT, 0); }
		public TerminalNode WS() { return getToken(dAngrParser.WS, 0); }
		public Expression_partContext expression_part() {
			return getRuleContext(Expression_partContext.class,0);
		}
		public ExpressionNotContext(Expression_partContext ctx) { copyFrom(ctx); }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterExpressionNot(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitExpressionNot(this);
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
			setState(236);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,32,_ctx) ) {
			case 1:
				{
				_localctx = new ExpressionIfContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(156);
				match(CIF);
				setState(158);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(157);
					match(WS);
					}
				}

				setState(160);
				condition();
				setState(162);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(161);
					match(WS);
					}
				}

				setState(164);
				match(CTHEN);
				setState(166);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(165);
					match(WS);
					}
				}

				setState(168);
				expression_part(0);
				setState(170);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(169);
					match(WS);
					}
				}

				setState(172);
				match(CELSE);
				setState(174);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(173);
					match(WS);
					}
				}

				setState(176);
				expression_part(10);
				}
				break;
			case 2:
				{
				_localctx = new ExpressionParenthesisContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(178);
				match(LPAREN);
				setState(180);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(179);
					match(WS);
					}
				}

				setState(182);
				expression();
				setState(184);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(183);
					match(WS);
					}
				}

				setState(186);
				match(RPAREN);
				}
				break;
			case 3:
				{
				_localctx = new ExpressionRangeContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(188);
				match(RANGE);
				setState(189);
				match(LPAREN);
				setState(191);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(190);
					match(WS);
					}
				}

				setState(193);
				expression_part(0);
				setState(195);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(194);
					match(WS);
					}
				}

				setState(215);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==COMMA) {
					{
					setState(197);
					match(COMMA);
					setState(199);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(198);
						match(WS);
						}
					}

					setState(201);
					expression_part(0);
					setState(203);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(202);
						match(WS);
						}
					}

					setState(213);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==COMMA) {
						{
						setState(205);
						match(COMMA);
						setState(207);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(206);
							match(WS);
							}
						}

						setState(209);
						expression_part(0);
						setState(211);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(210);
							match(WS);
							}
						}

						}
					}

					}
				}

				setState(217);
				match(RPAREN);
				}
				break;
			case 4:
				{
				_localctx = new ExpressionAltContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(219);
				range();
				}
				break;
			case 5:
				{
				_localctx = new ExpressionReferenceContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(220);
				reference();
				}
				break;
			case 6:
				{
				_localctx = new ExpressionBoolContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(221);
				match(BOOL);
				}
				break;
			case 7:
				{
				_localctx = new ExpressionNotContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(222);
				match(NOT);
				setState(223);
				match(WS);
				setState(224);
				expression_part(3);
				}
				break;
			case 8:
				{
				_localctx = new ExpressionOperationContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(225);
				object(0);
				{
				setState(227);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(226);
					match(WS);
					}
				}

				setState(229);
				operation();
				setState(231);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(230);
					match(WS);
					}
				}

				setState(233);
				expression_part(0);
				}
				}
				break;
			case 9:
				{
				_localctx = new ExpressionObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(235);
				object(0);
				}
				break;
			}
			_ctx.stop = _input.LT(-1);
			setState(245);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,33,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					{
					_localctx = new ExpressionInContext(new Expression_partContext(_parentctx, _parentState));
					pushNewRecursionContext(_localctx, _startState, RULE_expression_part);
					setState(238);
					if (!(precpred(_ctx, 7))) throw new FailedPredicateException(this, "precpred(_ctx, 7)");
					setState(239);
					match(WS);
					setState(240);
					_la = _input.LA(1);
					if ( !(_la==IN || _la==NOT_IN) ) {
					_errHandler.recoverInline(this);
					}
					else {
						if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
						_errHandler.reportMatch(this);
						consume();
					}
					setState(241);
					match(WS);
					setState(242);
					expression_part(8);
					}
					} 
				}
				setState(247);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,33,_ctx);
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
			setState(250);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,34,_ctx) ) {
			case 1:
				{
				setState(248);
				static_var();
				}
				break;
			case 2:
				{
				setState(249);
				object(0);
				}
				break;
			}
			setState(253);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(252);
				match(WS);
				}
			}

			setState(255);
			match(ASSIGN);
			setState(257);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(256);
				match(WS);
				}
			}

			setState(259);
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
			setState(261);
			match(STATIC);
			setState(262);
			match(WS);
			setState(263);
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
			setState(271);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case BANG:
				enterOuterAlt(_localctx, 1);
				{
				setState(265);
				match(BANG);
				setState(266);
				py_basic_content();
				}
				break;
			case AMP:
				enterOuterAlt(_localctx, 2);
				{
				setState(267);
				match(AMP);
				setState(268);
				expression();
				}
				break;
			case DOLLAR:
				enterOuterAlt(_localctx, 3);
				{
				setState(269);
				match(DOLLAR);
				setState(270);
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
			setState(316);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case IF:
				enterOuterAlt(_localctx, 1);
				{
				setState(273);
				match(IF);
				setState(274);
				match(WS);
				setState(275);
				condition();
				setState(277);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(276);
					match(WS);
					}
				}

				setState(279);
				match(COLON);
				setState(280);
				body();
				setState(282);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,39,_ctx) ) {
				case 1:
					{
					setState(281);
					else_();
					}
					break;
				}
				}
				break;
			case FOR:
				enterOuterAlt(_localctx, 2);
				{
				setState(284);
				match(FOR);
				setState(285);
				match(WS);
				setState(286);
				identifier();
				setState(295);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,42,_ctx) ) {
				case 1:
					{
					setState(288);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(287);
						match(WS);
						}
					}

					setState(290);
					match(COMMA);
					setState(292);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(291);
						match(WS);
						}
					}

					setState(294);
					identifier();
					}
					break;
				}
				setState(297);
				match(WS);
				setState(298);
				match(IN);
				setState(299);
				match(WS);
				setState(300);
				iterable();
				setState(302);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(301);
					match(WS);
					}
				}

				setState(304);
				match(COLON);
				setState(305);
				body();
				}
				break;
			case WHILE:
				enterOuterAlt(_localctx, 3);
				{
				setState(307);
				match(WHILE);
				setState(308);
				match(WS);
				setState(309);
				condition();
				setState(311);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(310);
					match(WS);
					}
				}

				setState(313);
				match(COLON);
				setState(314);
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
			setState(318);
			match(ELSE);
			setState(320);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(319);
				match(WS);
				}
			}

			setState(322);
			match(COLON);
			setState(323);
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
			setState(325);
			match(DEF);
			setState(326);
			match(WS);
			setState(327);
			identifier();
			setState(329);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(328);
				match(WS);
				}
			}

			setState(331);
			match(LPAREN);
			setState(333);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 17301502L) != 0) || _la==UNDERSCORE) {
				{
				setState(332);
				parameters();
				}
			}

			setState(335);
			match(RPAREN);
			setState(337);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(336);
				match(WS);
				}
			}

			setState(339);
			match(COLON);
			setState(340);
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
			setState(342);
			match(INDENT);
			setState(347); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(343);
				fstatement();
				setState(345);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==NEWLINE) {
					{
					setState(344);
					match(NEWLINE);
					}
				}

				}
				}
				setState(349); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( (((_la) & ~0x3f) == 0 && ((1L << _la) & 11266979074146302L) != 0) || _la==UNDERSCORE || _la==DASH );
			setState(351);
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
			setState(359);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,52,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(353);
				match(BREAK);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(354);
				match(CONTINUE);
				}
				break;
			case 3:
				enterOuterAlt(_localctx, 3);
				{
				{
				setState(355);
				match(RETURN);
				setState(356);
				match(WS);
				setState(357);
				expression();
				}
				}
				break;
			case 4:
				enterOuterAlt(_localctx, 4);
				{
				setState(358);
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
			setState(361);
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
			setState(363);
			identifier();
			setState(374);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==WS || _la==COMMA) {
				{
				{
				setState(365);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(364);
					match(WS);
					}
				}

				setState(367);
				match(COMMA);
				setState(369);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(368);
					match(WS);
					}
				}

				setState(371);
				identifier();
				}
				}
				setState(376);
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
			setState(377);
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
		public TerminalNode XOR() { return getToken(dAngrParser.XOR, 0); }
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
			setState(399);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case ADD:
				enterOuterAlt(_localctx, 1);
				{
				setState(379);
				match(ADD);
				}
				break;
			case DASH:
				enterOuterAlt(_localctx, 2);
				{
				setState(380);
				match(DASH);
				}
				break;
			case MUL:
				enterOuterAlt(_localctx, 3);
				{
				setState(381);
				match(MUL);
				}
				break;
			case DIV:
				enterOuterAlt(_localctx, 4);
				{
				setState(382);
				match(DIV);
				}
				break;
			case PERC:
				enterOuterAlt(_localctx, 5);
				{
				setState(383);
				match(PERC);
				}
				break;
			case POW:
				enterOuterAlt(_localctx, 6);
				{
				setState(384);
				match(POW);
				}
				break;
			case EQ:
				enterOuterAlt(_localctx, 7);
				{
				setState(385);
				match(EQ);
				}
				break;
			case NEQ:
				enterOuterAlt(_localctx, 8);
				{
				setState(386);
				match(NEQ);
				}
				break;
			case GT:
				enterOuterAlt(_localctx, 9);
				{
				setState(387);
				match(GT);
				}
				break;
			case LT:
				enterOuterAlt(_localctx, 10);
				{
				setState(388);
				match(LT);
				}
				break;
			case LE:
				enterOuterAlt(_localctx, 11);
				{
				setState(389);
				match(LE);
				}
				break;
			case GE:
				enterOuterAlt(_localctx, 12);
				{
				setState(390);
				match(GE);
				}
				break;
			case AND:
				enterOuterAlt(_localctx, 13);
				{
				setState(391);
				match(AND);
				}
				break;
			case XOR:
				enterOuterAlt(_localctx, 14);
				{
				setState(392);
				match(XOR);
				}
				break;
			case OR:
				enterOuterAlt(_localctx, 15);
				{
				setState(393);
				match(OR);
				setState(394);
				match(FLOORDIV);
				}
				break;
			case LSHIFT:
				enterOuterAlt(_localctx, 16);
				{
				setState(395);
				match(LSHIFT);
				}
				break;
			case RSHIFT:
				enterOuterAlt(_localctx, 17);
				{
				setState(396);
				match(RSHIFT);
				}
				break;
			case AMP:
				enterOuterAlt(_localctx, 18);
				{
				setState(397);
				match(AMP);
				}
				break;
			case BAR:
				enterOuterAlt(_localctx, 19);
				{
				setState(398);
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
			setState(401);
			identifier();
			setState(403);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==WS) {
				{
				setState(402);
				match(WS);
				}
			}

			setState(405);
			match(LPAREN);
			setState(407);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,58,_ctx) ) {
			case 1:
				{
				setState(406);
				match(WS);
				}
				break;
			}
			setState(412);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while ((((_la) & ~0x3f) == 0 && ((1L << _la) & -36029613106790402L) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & 163839L) != 0)) {
				{
				{
				setState(409);
				py_content();
				}
				}
				setState(414);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(415);
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
		public List<TerminalNode> RPAREN() { return getTokens(dAngrParser.RPAREN); }
		public TerminalNode RPAREN(int i) {
			return getToken(dAngrParser.RPAREN, i);
		}
		public List<Py_contentContext> py_content() {
			return getRuleContexts(Py_contentContext.class);
		}
		public Py_contentContext py_content(int i) {
			return getRuleContext(Py_contentContext.class,i);
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
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(428); 
			_errHandler.sync(this);
			_alt = 1;
			do {
				switch (_alt) {
				case 1:
					{
					setState(428);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,61,_ctx) ) {
					case 1:
						{
						setState(417);
						reference();
						}
						break;
					case 2:
						{
						setState(418);
						range();
						}
						break;
					case 3:
						{
						setState(419);
						anything();
						}
						break;
					case 4:
						{
						setState(420);
						match(LPAREN);
						setState(424);
						_errHandler.sync(this);
						_la = _input.LA(1);
						while ((((_la) & ~0x3f) == 0 && ((1L << _la) & -36029613106790402L) != 0) || ((((_la - 64)) & ~0x3f) == 0 && ((1L << (_la - 64)) & 163839L) != 0)) {
							{
							{
							setState(421);
							py_content();
							}
							}
							setState(426);
							_errHandler.sync(this);
							_la = _input.LA(1);
						}
						setState(427);
						match(RPAREN);
						}
						break;
					}
					}
					break;
				default:
					throw new NoViableAltException(this);
				}
				setState(430); 
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,62,_ctx);
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
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(441);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,64,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					setState(439);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,63,_ctx) ) {
					case 1:
						{
						setState(432);
						reference();
						}
						break;
					case 2:
						{
						setState(433);
						range();
						}
						break;
					case 3:
						{
						setState(434);
						anything();
						}
						break;
					case 4:
						{
						setState(435);
						match(LPAREN);
						setState(436);
						bash_content();
						setState(437);
						match(RPAREN);
						}
						break;
					}
					} 
				}
				setState(443);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,64,_ctx);
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
			setState(471);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case SYM_DB:
			case REG_DB:
			case VARS_DB:
				enterOuterAlt(_localctx, 1);
				{
				setState(444);
				_la = _input.LA(1);
				if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 469762048L) != 0)) ) {
				_errHandler.recoverInline(this);
				}
				else {
					if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
					_errHandler.reportMatch(this);
					consume();
				}
				setState(445);
				match(DOT);
				setState(446);
				identifier();
				setState(448);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,65,_ctx) ) {
				case 1:
					{
					setState(447);
					match(BANG);
					}
					break;
				}
				}
				break;
			case STATE:
				enterOuterAlt(_localctx, 2);
				{
				setState(450);
				match(STATE);
				}
				break;
			case MEM_DB:
				enterOuterAlt(_localctx, 3);
				{
				setState(451);
				match(MEM_DB);
				setState(452);
				match(BRA);
				setState(454);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(453);
					match(WS);
					}
				}

				setState(456);
				index();
				setState(465);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS || _la==ARROW) {
					{
					setState(458);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(457);
						match(WS);
						}
					}

					setState(460);
					match(ARROW);
					setState(462);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(461);
						match(WS);
						}
					}

					setState(464);
					index();
					}
				}

				setState(467);
				match(KET);
				setState(469);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,70,_ctx) ) {
				case 1:
					{
					setState(468);
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
			setState(474);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,72,_ctx) ) {
			case 1:
				{
				setState(473);
				match(DASH);
				}
				break;
			}
			setState(476);
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
			setState(483);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case LETTERS:
				{
				setState(478);
				match(LETTERS);
				}
				break;
			case UNDERSCORE:
				{
				setState(479);
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
			case NOT_IN:
			case NOT:
			case WHILE:
			case BOOL:
			case HELP:
			case RETURN:
			case BREAK:
			case CONTINUE:
				{
				setState(480);
				special_words();
				setState(481);
				match(UNDERSCORE);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			setState(491);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,75,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					setState(489);
					_errHandler.sync(this);
					switch (_input.LA(1)) {
					case LETTERS:
						{
						setState(485);
						match(LETTERS);
						}
						break;
					case NUMBERS:
						{
						setState(486);
						match(NUMBERS);
						}
						break;
					case UNDERSCORE:
						{
						setState(487);
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
					case NOT_IN:
					case NOT:
					case WHILE:
					case BOOL:
					case HELP:
					case RETURN:
					case BREAK:
					case CONTINUE:
						{
						setState(488);
						special_words();
						}
						break;
					default:
						throw new NoViableAltException(this);
					}
					} 
				}
				setState(493);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,75,_ctx);
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
			setState(494);
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
			setState(572);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,93,_ctx) ) {
			case 1:
				{
				_localctx = new IDObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(497);
				identifier();
				setState(499);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,76,_ctx) ) {
				case 1:
					{
					setState(498);
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
				setState(502);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==DASH) {
					{
					setState(501);
					match(DASH);
					}
				}

				setState(504);
				numeric();
				}
				break;
			case 3:
				{
				_localctx = new BoolObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(505);
				match(BOOL);
				}
				break;
			case 4:
				{
				_localctx = new ReferenceObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(506);
				reference();
				}
				break;
			case 5:
				{
				_localctx = new ListObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(507);
				match(BRA);
				setState(509);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,78,_ctx) ) {
				case 1:
					{
					setState(508);
					match(WS);
					}
					break;
				}
				setState(512);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 11259007614844926L) != 0) || _la==UNDERSCORE || _la==DASH) {
					{
					setState(511);
					object(0);
					}
				}

				setState(524);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,82,_ctx);
				while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
					if ( _alt==1 ) {
						{
						{
						setState(515);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(514);
							match(WS);
							}
						}

						setState(517);
						match(COMMA);
						setState(519);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(518);
							match(WS);
							}
						}

						setState(521);
						object(0);
						}
						} 
					}
					setState(526);
					_errHandler.sync(this);
					_alt = getInterpreter().adaptivePredict(_input,82,_ctx);
				}
				setState(528);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(527);
					match(WS);
					}
				}

				setState(530);
				match(KET);
				}
				break;
			case 6:
				{
				_localctx = new DictionaryObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(531);
				match(BRACE);
				setState(533);
				_errHandler.sync(this);
				switch ( getInterpreter().adaptivePredict(_input,84,_ctx) ) {
				case 1:
					{
					setState(532);
					match(WS);
					}
					break;
				}
				setState(563);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==STRING) {
					{
					{
					setState(535);
					match(STRING);
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
					match(COLON);
					setState(541);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(540);
						match(WS);
						}
					}

					setState(543);
					object(0);
					{
					setState(545);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(544);
						match(WS);
						}
					}

					setState(547);
					match(COMMA);
					setState(549);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(548);
						match(WS);
						}
					}

					setState(551);
					match(STRING);
					setState(553);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(552);
						match(WS);
						}
					}

					setState(555);
					match(COLON);
					setState(557);
					_errHandler.sync(this);
					_la = _input.LA(1);
					if (_la==WS) {
						{
						setState(556);
						match(WS);
						}
					}

					setState(559);
					object(0);
					}
					}
					}
					setState(565);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(567);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if (_la==WS) {
					{
					setState(566);
					match(WS);
					}
				}

				setState(569);
				match(KETCE);
				}
				break;
			case 7:
				{
				_localctx = new StringObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(570);
				match(STRING);
				}
				break;
			case 8:
				{
				_localctx = new BinaryStringObjectContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(571);
				match(BINARY_STRING);
				}
				break;
			}
			_ctx.stop = _input.LT(-1);
			setState(630);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,106,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					setState(628);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,105,_ctx) ) {
					case 1:
						{
						_localctx = new PropertyObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(574);
						if (!(precpred(_ctx, 8))) throw new FailedPredicateException(this, "precpred(_ctx, 8)");
						setState(575);
						match(DOT);
						setState(576);
						identifier();
						}
						break;
					case 2:
						{
						_localctx = new IndexedPropertyObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(577);
						if (!(precpred(_ctx, 7))) throw new FailedPredicateException(this, "precpred(_ctx, 7)");
						setState(578);
						match(BRA);
						setState(580);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(579);
							match(WS);
							}
						}

						setState(582);
						index();
						setState(584);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(583);
							match(WS);
							}
						}

						setState(586);
						match(KET);
						}
						break;
					case 3:
						{
						_localctx = new SliceStartEndObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(588);
						if (!(precpred(_ctx, 6))) throw new FailedPredicateException(this, "precpred(_ctx, 6)");
						setState(589);
						match(BRA);
						setState(591);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(590);
							match(WS);
							}
						}

						setState(593);
						index();
						setState(595);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(594);
							match(WS);
							}
						}

						setState(597);
						match(COLON);
						setState(599);
						_errHandler.sync(this);
						switch ( getInterpreter().adaptivePredict(_input,98,_ctx) ) {
						case 1:
							{
							setState(598);
							match(WS);
							}
							break;
						}
						setState(602);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 11266979074146302L) != 0) || _la==UNDERSCORE || _la==DASH) {
							{
							setState(601);
							index();
							}
						}

						setState(605);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(604);
							match(WS);
							}
						}

						setState(607);
						match(KET);
						}
						break;
					case 4:
						{
						_localctx = new SlideStartLengthObjectContext(new ObjectContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_object);
						setState(609);
						if (!(precpred(_ctx, 5))) throw new FailedPredicateException(this, "precpred(_ctx, 5)");
						setState(610);
						match(BRA);
						setState(612);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(611);
							match(WS);
							}
						}

						setState(614);
						index();
						setState(616);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(615);
							match(WS);
							}
						}

						setState(618);
						match(ARROW);
						setState(620);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(619);
							match(WS);
							}
						}

						setState(622);
						index();
						setState(624);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if (_la==WS) {
							{
							setState(623);
							match(WS);
							}
						}

						setState(626);
						match(KET);
						}
						break;
					}
					} 
				}
				setState(632);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,106,_ctx);
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
		public Anything_noContext anything_no() {
			return getRuleContext(Anything_noContext.class,0);
		}
		public TerminalNode NEWLINE() { return getToken(dAngrParser.NEWLINE, 0); }
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
			setState(635);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
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
			case NOT_IN:
			case NOT:
			case WHILE:
			case BOOL:
			case HELP:
			case RETURN:
			case BREAK:
			case CONTINUE:
			case WS:
			case NUMBERS:
			case LETTERS:
			case STRING:
			case BINARY_STRING:
			case LPAREN:
			case BANG:
			case AMP:
			case DOLLAR:
			case COLON:
			case SCOLON:
			case COMMA:
			case QUOTE:
			case SQUOTE:
			case AT:
			case DOT:
			case BAR:
			case BRA:
			case KET:
			case BRACE:
			case KETCE:
			case HASH:
			case PERC:
			case MUL:
			case ADD:
			case DIV:
			case FLOORDIV:
			case LSHIFT:
			case RSHIFT:
			case POW:
			case ASSIGN:
			case EQ:
			case NEQ:
			case LT:
			case GT:
			case LE:
			case GE:
			case AND:
			case OR:
			case QMARK:
			case TILDE:
			case TICK:
			case UNDERSCORE:
			case DASH:
			case HAT:
				{
				setState(633);
				anything_no();
				}
				break;
			case NEWLINE:
				{
				setState(634);
				match(NEWLINE);
				}
				break;
			default:
				throw new NoViableAltException(this);
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
	public static class Anything_noContext extends ParserRuleContext {
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
		public Anything_noContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_anything_no; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).enterAnything_no(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof dAngrListener ) ((dAngrListener)listener).exitAnything_no(this);
		}
	}

	public final Anything_noContext anything_no() throws RecognitionException {
		Anything_noContext _localctx = new Anything_noContext(_ctx, getState());
		enterRule(_localctx, 50, RULE_anything_no);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(648);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,108,_ctx) ) {
			case 1:
				{
				setState(637);
				match(LETTERS);
				}
				break;
			case 2:
				{
				setState(638);
				match(NUMBERS);
				}
				break;
			case 3:
				{
				setState(639);
				symbol();
				}
				break;
			case 4:
				{
				setState(640);
				match(STRING);
				}
				break;
			case 5:
				{
				setState(641);
				match(BINARY_STRING);
				}
				break;
			case 6:
				{
				setState(642);
				match(WS);
				}
				break;
			case 7:
				{
				setState(643);
				match(LPAREN);
				setState(644);
				anything();
				setState(645);
				match(RPAREN);
				}
				break;
			case 8:
				{
				setState(647);
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
		public TerminalNode NOT() { return getToken(dAngrParser.NOT, 0); }
		public TerminalNode NOT_IN() { return getToken(dAngrParser.NOT_IN, 0); }
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
		enterRule(_localctx, 52, RULE_special_words);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(650);
			_la = _input.LA(1);
			if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 524286L) != 0)) ) {
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
		enterRule(_localctx, 54, RULE_range);
		try {
			setState(655);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case AMP:
				enterOuterAlt(_localctx, 1);
				{
				setState(652);
				dangr_range();
				}
				break;
			case DOLLAR:
				enterOuterAlt(_localctx, 2);
				{
				setState(653);
				bash_range();
				}
				break;
			case BANG:
				enterOuterAlt(_localctx, 3);
				{
				setState(654);
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
		enterRule(_localctx, 56, RULE_dangr_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(657);
			match(AMP);
			setState(658);
			match(LPAREN);
			setState(659);
			expression();
			setState(660);
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
		enterRule(_localctx, 58, RULE_bash_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(662);
			match(DOLLAR);
			setState(663);
			match(LPAREN);
			setState(664);
			bash_content();
			setState(665);
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
		enterRule(_localctx, 60, RULE_python_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(667);
			match(BANG);
			setState(668);
			match(LPAREN);
			setState(669);
			py_content();
			setState(670);
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
		enterRule(_localctx, 62, RULE_symbol);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(672);
			_la = _input.LA(1);
			if ( !(((((_la - 20)) & ~0x3f) == 0 && ((1L << (_la - 20)) & 2882303727156330497L) != 0)) ) {
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
			return precpred(_ctx, 7);
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
		"\u0004\u0001Q\u02a3\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0002"+
		"\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004\u0002"+
		"\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007\u0007\u0007\u0002"+
		"\b\u0007\b\u0002\t\u0007\t\u0002\n\u0007\n\u0002\u000b\u0007\u000b\u0002"+
		"\f\u0007\f\u0002\r\u0007\r\u0002\u000e\u0007\u000e\u0002\u000f\u0007\u000f"+
		"\u0002\u0010\u0007\u0010\u0002\u0011\u0007\u0011\u0002\u0012\u0007\u0012"+
		"\u0002\u0013\u0007\u0013\u0002\u0014\u0007\u0014\u0002\u0015\u0007\u0015"+
		"\u0002\u0016\u0007\u0016\u0002\u0017\u0007\u0017\u0002\u0018\u0007\u0018"+
		"\u0002\u0019\u0007\u0019\u0002\u001a\u0007\u001a\u0002\u001b\u0007\u001b"+
		"\u0002\u001c\u0007\u001c\u0002\u001d\u0007\u001d\u0002\u001e\u0007\u001e"+
		"\u0002\u001f\u0007\u001f\u0001\u0000\u0001\u0000\u0001\u0000\u0003\u0000"+
		"D\b\u0000\u0001\u0000\u0001\u0000\u0001\u0000\u0001\u0000\u0001\u0000"+
		"\u0001\u0000\u0005\u0000L\b\u0000\n\u0000\f\u0000O\t\u0000\u0005\u0000"+
		"Q\b\u0000\n\u0000\f\u0000T\t\u0000\u0001\u0000\u0005\u0000W\b\u0000\n"+
		"\u0000\f\u0000Z\t\u0000\u0003\u0000\\\b\u0000\u0001\u0000\u0001\u0000"+
		"\u0001\u0001\u0001\u0001\u0001\u0001\u0005\u0001c\b\u0001\n\u0001\f\u0001"+
		"f\t\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0005\u0001"+
		"l\b\u0001\n\u0001\f\u0001o\t\u0001\u0001\u0001\u0001\u0001\u0001\u0001"+
		"\u0001\u0001\u0005\u0001u\b\u0001\n\u0001\f\u0001x\t\u0001\u0001\u0001"+
		"\u0001\u0001\u0001\u0001\u0001\u0001\u0005\u0001~\b\u0001\n\u0001\f\u0001"+
		"\u0081\t\u0001\u0001\u0001\u0001\u0001\u0003\u0001\u0085\b\u0001\u0001"+
		"\u0002\u0001\u0002\u0001\u0002\u0003\u0002\u008a\b\u0002\u0001\u0002\u0001"+
		"\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0003\u0002\u0091\b\u0002\u0001"+
		"\u0002\u0005\u0002\u0094\b\u0002\n\u0002\f\u0002\u0097\t\u0002\u0001\u0002"+
		"\u0003\u0002\u009a\b\u0002\u0001\u0003\u0001\u0003\u0001\u0003\u0003\u0003"+
		"\u009f\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00a3\b\u0003\u0001"+
		"\u0003\u0001\u0003\u0003\u0003\u00a7\b\u0003\u0001\u0003\u0001\u0003\u0003"+
		"\u0003\u00ab\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00af\b\u0003"+
		"\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00b5\b\u0003"+
		"\u0001\u0003\u0001\u0003\u0003\u0003\u00b9\b\u0003\u0001\u0003\u0001\u0003"+
		"\u0001\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00c0\b\u0003\u0001\u0003"+
		"\u0001\u0003\u0003\u0003\u00c4\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003"+
		"\u00c8\b\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00cc\b\u0003\u0001"+
		"\u0003\u0001\u0003\u0003\u0003\u00d0\b\u0003\u0001\u0003\u0001\u0003\u0003"+
		"\u0003\u00d4\b\u0003\u0003\u0003\u00d6\b\u0003\u0003\u0003\u00d8\b\u0003"+
		"\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003"+
		"\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0003\u0003\u00e4\b\u0003"+
		"\u0001\u0003\u0001\u0003\u0003\u0003\u00e8\b\u0003\u0001\u0003\u0001\u0003"+
		"\u0001\u0003\u0003\u0003\u00ed\b\u0003\u0001\u0003\u0001\u0003\u0001\u0003"+
		"\u0001\u0003\u0001\u0003\u0005\u0003\u00f4\b\u0003\n\u0003\f\u0003\u00f7"+
		"\t\u0003\u0001\u0004\u0001\u0004\u0003\u0004\u00fb\b\u0004\u0001\u0004"+
		"\u0003\u0004\u00fe\b\u0004\u0001\u0004\u0001\u0004\u0003\u0004\u0102\b"+
		"\u0004\u0001\u0004\u0001\u0004\u0001\u0005\u0001\u0005\u0001\u0005\u0001"+
		"\u0005\u0001\u0006\u0001\u0006\u0001\u0006\u0001\u0006\u0001\u0006\u0001"+
		"\u0006\u0003\u0006\u0110\b\u0006\u0001\u0007\u0001\u0007\u0001\u0007\u0001"+
		"\u0007\u0003\u0007\u0116\b\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0003"+
		"\u0007\u011b\b\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0003"+
		"\u0007\u0121\b\u0007\u0001\u0007\u0001\u0007\u0003\u0007\u0125\b\u0007"+
		"\u0001\u0007\u0003\u0007\u0128\b\u0007\u0001\u0007\u0001\u0007\u0001\u0007"+
		"\u0001\u0007\u0001\u0007\u0003\u0007\u012f\b\u0007\u0001\u0007\u0001\u0007"+
		"\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0003\u0007"+
		"\u0138\b\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0003\u0007\u013d\b"+
		"\u0007\u0001\b\u0001\b\u0003\b\u0141\b\b\u0001\b\u0001\b\u0001\b\u0001"+
		"\t\u0001\t\u0001\t\u0001\t\u0003\t\u014a\b\t\u0001\t\u0001\t\u0003\t\u014e"+
		"\b\t\u0001\t\u0001\t\u0003\t\u0152\b\t\u0001\t\u0001\t\u0001\t\u0001\n"+
		"\u0001\n\u0001\n\u0003\n\u015a\b\n\u0004\n\u015c\b\n\u000b\n\f\n\u015d"+
		"\u0001\n\u0001\n\u0001\u000b\u0001\u000b\u0001\u000b\u0001\u000b\u0001"+
		"\u000b\u0001\u000b\u0003\u000b\u0168\b\u000b\u0001\f\u0001\f\u0001\r\u0001"+
		"\r\u0003\r\u016e\b\r\u0001\r\u0001\r\u0003\r\u0172\b\r\u0001\r\u0005\r"+
		"\u0175\b\r\n\r\f\r\u0178\t\r\u0001\u000e\u0001\u000e\u0001\u000f\u0001"+
		"\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001"+
		"\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001"+
		"\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u000f\u0001"+
		"\u000f\u0003\u000f\u0190\b\u000f\u0001\u0010\u0001\u0010\u0003\u0010\u0194"+
		"\b\u0010\u0001\u0010\u0001\u0010\u0003\u0010\u0198\b\u0010\u0001\u0010"+
		"\u0005\u0010\u019b\b\u0010\n\u0010\f\u0010\u019e\t\u0010\u0001\u0010\u0001"+
		"\u0010\u0001\u0011\u0001\u0011\u0001\u0011\u0001\u0011\u0001\u0011\u0005"+
		"\u0011\u01a7\b\u0011\n\u0011\f\u0011\u01aa\t\u0011\u0001\u0011\u0004\u0011"+
		"\u01ad\b\u0011\u000b\u0011\f\u0011\u01ae\u0001\u0012\u0001\u0012\u0001"+
		"\u0012\u0001\u0012\u0001\u0012\u0001\u0012\u0001\u0012\u0005\u0012\u01b8"+
		"\b\u0012\n\u0012\f\u0012\u01bb\t\u0012\u0001\u0013\u0001\u0013\u0001\u0013"+
		"\u0001\u0013\u0003\u0013\u01c1\b\u0013\u0001\u0013\u0001\u0013\u0001\u0013"+
		"\u0001\u0013\u0003\u0013\u01c7\b\u0013\u0001\u0013\u0001\u0013\u0003\u0013"+
		"\u01cb\b\u0013\u0001\u0013\u0001\u0013\u0003\u0013\u01cf\b\u0013\u0001"+
		"\u0013\u0003\u0013\u01d2\b\u0013\u0001\u0013\u0001\u0013\u0003\u0013\u01d6"+
		"\b\u0013\u0003\u0013\u01d8\b\u0013\u0001\u0014\u0003\u0014\u01db\b\u0014"+
		"\u0001\u0014\u0001\u0014\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0015"+
		"\u0001\u0015\u0003\u0015\u01e4\b\u0015\u0001\u0015\u0001\u0015\u0001\u0015"+
		"\u0001\u0015\u0005\u0015\u01ea\b\u0015\n\u0015\f\u0015\u01ed\t\u0015\u0001"+
		"\u0016\u0001\u0016\u0001\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u01f4"+
		"\b\u0017\u0001\u0017\u0003\u0017\u01f7\b\u0017\u0001\u0017\u0001\u0017"+
		"\u0001\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u01fe\b\u0017\u0001\u0017"+
		"\u0003\u0017\u0201\b\u0017\u0001\u0017\u0003\u0017\u0204\b\u0017\u0001"+
		"\u0017\u0001\u0017\u0003\u0017\u0208\b\u0017\u0001\u0017\u0005\u0017\u020b"+
		"\b\u0017\n\u0017\f\u0017\u020e\t\u0017\u0001\u0017\u0003\u0017\u0211\b"+
		"\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0216\b\u0017\u0001"+
		"\u0017\u0001\u0017\u0003\u0017\u021a\b\u0017\u0001\u0017\u0001\u0017\u0003"+
		"\u0017\u021e\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0222\b\u0017"+
		"\u0001\u0017\u0001\u0017\u0003\u0017\u0226\b\u0017\u0001\u0017\u0001\u0017"+
		"\u0003\u0017\u022a\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u022e\b"+
		"\u0017\u0001\u0017\u0001\u0017\u0005\u0017\u0232\b\u0017\n\u0017\f\u0017"+
		"\u0235\t\u0017\u0001\u0017\u0003\u0017\u0238\b\u0017\u0001\u0017\u0001"+
		"\u0017\u0001\u0017\u0003\u0017\u023d\b\u0017\u0001\u0017\u0001\u0017\u0001"+
		"\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0245\b\u0017\u0001"+
		"\u0017\u0001\u0017\u0003\u0017\u0249\b\u0017\u0001\u0017\u0001\u0017\u0001"+
		"\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0250\b\u0017\u0001\u0017\u0001"+
		"\u0017\u0003\u0017\u0254\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0258"+
		"\b\u0017\u0001\u0017\u0003\u0017\u025b\b\u0017\u0001\u0017\u0003\u0017"+
		"\u025e\b\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017"+
		"\u0003\u0017\u0265\b\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u0269\b"+
		"\u0017\u0001\u0017\u0001\u0017\u0003\u0017\u026d\b\u0017\u0001\u0017\u0001"+
		"\u0017\u0003\u0017\u0271\b\u0017\u0001\u0017\u0001\u0017\u0005\u0017\u0275"+
		"\b\u0017\n\u0017\f\u0017\u0278\t\u0017\u0001\u0018\u0001\u0018\u0003\u0018"+
		"\u027c\b\u0018\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019"+
		"\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019"+
		"\u0003\u0019\u0289\b\u0019\u0001\u001a\u0001\u001a\u0001\u001b\u0001\u001b"+
		"\u0001\u001b\u0003\u001b\u0290\b\u001b\u0001\u001c\u0001\u001c\u0001\u001c"+
		"\u0001\u001c\u0001\u001c\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001d"+
		"\u0001\u001d\u0001\u001e\u0001\u001e\u0001\u001e\u0001\u001e\u0001\u001e"+
		"\u0001\u001f\u0001\u001f\u0001\u001f\u0000\u0002\u0006. \u0000\u0002\u0004"+
		"\u0006\b\n\f\u000e\u0010\u0012\u0014\u0016\u0018\u001a\u001c\u001e \""+
		"$&(*,.02468:<>\u0000\u0006\u0002\u0000\u000f\u000fJJ\u0001\u0000\n\u000b"+
		"\u0001\u0000\u001a\u001c\u0001\u0000\u0015\u0016\u0001\u0000\u0001\u0012"+
		"\u0004\u0000\u0014\u0014(68NQQ\u0328\u0000[\u0001\u0000\u0000\u0000\u0002"+
		"\u0084\u0001\u0000\u0000\u0000\u0004\u0099\u0001\u0000\u0000\u0000\u0006"+
		"\u00ec\u0001\u0000\u0000\u0000\b\u00fa\u0001\u0000\u0000\u0000\n\u0105"+
		"\u0001\u0000\u0000\u0000\f\u010f\u0001\u0000\u0000\u0000\u000e\u013c\u0001"+
		"\u0000\u0000\u0000\u0010\u013e\u0001\u0000\u0000\u0000\u0012\u0145\u0001"+
		"\u0000\u0000\u0000\u0014\u0156\u0001\u0000\u0000\u0000\u0016\u0167\u0001"+
		"\u0000\u0000\u0000\u0018\u0169\u0001\u0000\u0000\u0000\u001a\u016b\u0001"+
		"\u0000\u0000\u0000\u001c\u0179\u0001\u0000\u0000\u0000\u001e\u018f\u0001"+
		"\u0000\u0000\u0000 \u0191\u0001\u0000\u0000\u0000\"\u01ac\u0001\u0000"+
		"\u0000\u0000$\u01b9\u0001\u0000\u0000\u0000&\u01d7\u0001\u0000\u0000\u0000"+
		"(\u01da\u0001\u0000\u0000\u0000*\u01e3\u0001\u0000\u0000\u0000,\u01ee"+
		"\u0001\u0000\u0000\u0000.\u023c\u0001\u0000\u0000\u00000\u027b\u0001\u0000"+
		"\u0000\u00002\u0288\u0001\u0000\u0000\u00004\u028a\u0001\u0000\u0000\u0000"+
		"6\u028f\u0001\u0000\u0000\u00008\u0291\u0001\u0000\u0000\u0000:\u0296"+
		"\u0001\u0000\u0000\u0000<\u029b\u0001\u0000\u0000\u0000>\u02a0\u0001\u0000"+
		"\u0000\u0000@C\u0007\u0000\u0000\u0000AB\u0005\u0014\u0000\u0000BD\u0003"+
		"*\u0015\u0000CA\u0001\u0000\u0000\u0000CD\u0001\u0000\u0000\u0000DE\u0001"+
		"\u0000\u0000\u0000E\\\u0005\u0013\u0000\u0000FQ\u0005\u0013\u0000\u0000"+
		"GQ\u0003\u0002\u0001\u0000HQ\u0003\u0012\t\u0000IM\u00058\u0000\u0000"+
		"JL\u00032\u0019\u0000KJ\u0001\u0000\u0000\u0000LO\u0001\u0000\u0000\u0000"+
		"MK\u0001\u0000\u0000\u0000MN\u0001\u0000\u0000\u0000NQ\u0001\u0000\u0000"+
		"\u0000OM\u0001\u0000\u0000\u0000PF\u0001\u0000\u0000\u0000PG\u0001\u0000"+
		"\u0000\u0000PH\u0001\u0000\u0000\u0000PI\u0001\u0000\u0000\u0000QT\u0001"+
		"\u0000\u0000\u0000RP\u0001\u0000\u0000\u0000RS\u0001\u0000\u0000\u0000"+
		"SX\u0001\u0000\u0000\u0000TR\u0001\u0000\u0000\u0000UW\u0005\u0014\u0000"+
		"\u0000VU\u0001\u0000\u0000\u0000WZ\u0001\u0000\u0000\u0000XV\u0001\u0000"+
		"\u0000\u0000XY\u0001\u0000\u0000\u0000Y\\\u0001\u0000\u0000\u0000ZX\u0001"+
		"\u0000\u0000\u0000[@\u0001\u0000\u0000\u0000[R\u0001\u0000\u0000\u0000"+
		"\\]\u0001\u0000\u0000\u0000]^\u0005\u0000\u0000\u0001^\u0001\u0001\u0000"+
		"\u0000\u0000_\u0085\u0003\u000e\u0007\u0000`d\u0003\b\u0004\u0000ac\u0005"+
		"\u0014\u0000\u0000ba\u0001\u0000\u0000\u0000cf\u0001\u0000\u0000\u0000"+
		"db\u0001\u0000\u0000\u0000de\u0001\u0000\u0000\u0000eg\u0001\u0000\u0000"+
		"\u0000fd\u0001\u0000\u0000\u0000gh\u0005\u0013\u0000\u0000h\u0085\u0001"+
		"\u0000\u0000\u0000im\u0003\u0004\u0002\u0000jl\u0005\u0014\u0000\u0000"+
		"kj\u0001\u0000\u0000\u0000lo\u0001\u0000\u0000\u0000mk\u0001\u0000\u0000"+
		"\u0000mn\u0001\u0000\u0000\u0000np\u0001\u0000\u0000\u0000om\u0001\u0000"+
		"\u0000\u0000pq\u0005\u0013\u0000\u0000q\u0085\u0001\u0000\u0000\u0000"+
		"rv\u0003\n\u0005\u0000su\u0005\u0014\u0000\u0000ts\u0001\u0000\u0000\u0000"+
		"ux\u0001\u0000\u0000\u0000vt\u0001\u0000\u0000\u0000vw\u0001\u0000\u0000"+
		"\u0000wy\u0001\u0000\u0000\u0000xv\u0001\u0000\u0000\u0000yz\u0005\u0013"+
		"\u0000\u0000z\u0085\u0001\u0000\u0000\u0000{\u007f\u0003\f\u0006\u0000"+
		"|~\u0005\u0014\u0000\u0000}|\u0001\u0000\u0000\u0000~\u0081\u0001\u0000"+
		"\u0000\u0000\u007f}\u0001\u0000\u0000\u0000\u007f\u0080\u0001\u0000\u0000"+
		"\u0000\u0080\u0082\u0001\u0000\u0000\u0000\u0081\u007f\u0001\u0000\u0000"+
		"\u0000\u0082\u0083\u0005\u0013\u0000\u0000\u0083\u0085\u0001\u0000\u0000"+
		"\u0000\u0084_\u0001\u0000\u0000\u0000\u0084`\u0001\u0000\u0000\u0000\u0084"+
		"i\u0001\u0000\u0000\u0000\u0084r\u0001\u0000\u0000\u0000\u0084{\u0001"+
		"\u0000\u0000\u0000\u0085\u0003\u0001\u0000\u0000\u0000\u0086\u0087\u0003"+
		"*\u0015\u0000\u0087\u0088\u00051\u0000\u0000\u0088\u008a\u0001\u0000\u0000"+
		"\u0000\u0089\u0086\u0001\u0000\u0000\u0000\u0089\u008a\u0001\u0000\u0000"+
		"\u0000\u008a\u008b\u0001\u0000\u0000\u0000\u008b\u0095\u0003*\u0015\u0000"+
		"\u008c\u0090\u0005\u0014\u0000\u0000\u008d\u008e\u0003*\u0015\u0000\u008e"+
		"\u008f\u0005A\u0000\u0000\u008f\u0091\u0001\u0000\u0000\u0000\u0090\u008d"+
		"\u0001\u0000\u0000\u0000\u0090\u0091\u0001\u0000\u0000\u0000\u0091\u0092"+
		"\u0001\u0000\u0000\u0000\u0092\u0094\u0003\u0006\u0003\u0000\u0093\u008c"+
		"\u0001\u0000\u0000\u0000\u0094\u0097\u0001\u0000\u0000\u0000\u0095\u0093"+
		"\u0001\u0000\u0000\u0000\u0095\u0096\u0001\u0000\u0000\u0000\u0096\u009a"+
		"\u0001\u0000\u0000\u0000\u0097\u0095\u0001\u0000\u0000\u0000\u0098\u009a"+
		"\u0003\u0006\u0003\u0000\u0099\u0089\u0001\u0000\u0000\u0000\u0099\u0098"+
		"\u0001\u0000\u0000\u0000\u009a\u0005\u0001\u0000\u0000\u0000\u009b\u009c"+
		"\u0006\u0003\uffff\uffff\u0000\u009c\u009e\u0005\u0002\u0000\u0000\u009d"+
		"\u009f\u0005\u0014\u0000\u0000\u009e\u009d\u0001\u0000\u0000\u0000\u009e"+
		"\u009f\u0001\u0000\u0000\u0000\u009f\u00a0\u0001\u0000\u0000\u0000\u00a0"+
		"\u00a2\u0003\u001c\u000e\u0000\u00a1\u00a3\u0005\u0014\u0000\u0000\u00a2"+
		"\u00a1\u0001\u0000\u0000\u0000\u00a2\u00a3\u0001\u0000\u0000\u0000\u00a3"+
		"\u00a4\u0001\u0000\u0000\u0000\u00a4\u00a6\u0005\u0003\u0000\u0000\u00a5"+
		"\u00a7\u0005\u0014\u0000\u0000\u00a6\u00a5\u0001\u0000\u0000\u0000\u00a6"+
		"\u00a7\u0001\u0000\u0000\u0000\u00a7\u00a8\u0001\u0000\u0000\u0000\u00a8"+
		"\u00aa\u0003\u0006\u0003\u0000\u00a9\u00ab\u0005\u0014\u0000\u0000\u00aa"+
		"\u00a9\u0001\u0000\u0000\u0000\u00aa\u00ab\u0001\u0000\u0000\u0000\u00ab"+
		"\u00ac\u0001\u0000\u0000\u0000\u00ac\u00ae\u0005\u0004\u0000\u0000\u00ad"+
		"\u00af\u0005\u0014\u0000\u0000\u00ae\u00ad\u0001\u0000\u0000\u0000\u00ae"+
		"\u00af\u0001\u0000\u0000\u0000\u00af\u00b0\u0001\u0000\u0000\u0000\u00b0"+
		"\u00b1\u0003\u0006\u0003\n\u00b1\u00ed\u0001\u0000\u0000\u0000\u00b2\u00b4"+
		"\u0005&\u0000\u0000\u00b3\u00b5\u0005\u0014\u0000\u0000\u00b4\u00b3\u0001"+
		"\u0000\u0000\u0000\u00b4\u00b5\u0001\u0000\u0000\u0000\u00b5\u00b6\u0001"+
		"\u0000\u0000\u0000\u00b6\u00b8\u0003\u0004\u0002\u0000\u00b7\u00b9\u0005"+
		"\u0014\u0000\u0000\u00b8\u00b7\u0001\u0000\u0000\u0000\u00b8\u00b9\u0001"+
		"\u0000\u0000\u0000\u00b9\u00ba\u0001\u0000\u0000\u0000\u00ba\u00bb\u0005"+
		"\'\u0000\u0000\u00bb\u00ed\u0001\u0000\u0000\u0000\u00bc\u00bd\u0005\u0005"+
		"\u0000\u0000\u00bd\u00bf\u0005&\u0000\u0000\u00be\u00c0\u0005\u0014\u0000"+
		"\u0000\u00bf\u00be\u0001\u0000\u0000\u0000\u00bf\u00c0\u0001\u0000\u0000"+
		"\u0000\u00c0\u00c1\u0001\u0000\u0000\u0000\u00c1\u00c3\u0003\u0006\u0003"+
		"\u0000\u00c2\u00c4\u0005\u0014\u0000\u0000\u00c3\u00c2\u0001\u0000\u0000"+
		"\u0000\u00c3\u00c4\u0001\u0000\u0000\u0000\u00c4\u00d7\u0001\u0000\u0000"+
		"\u0000\u00c5\u00c7\u0005-\u0000\u0000\u00c6\u00c8\u0005\u0014\u0000\u0000"+
		"\u00c7\u00c6\u0001\u0000\u0000\u0000\u00c7\u00c8\u0001\u0000\u0000\u0000"+
		"\u00c8\u00c9\u0001\u0000\u0000\u0000\u00c9\u00cb\u0003\u0006\u0003\u0000"+
		"\u00ca\u00cc\u0005\u0014\u0000\u0000\u00cb\u00ca\u0001\u0000\u0000\u0000"+
		"\u00cb\u00cc\u0001\u0000\u0000\u0000\u00cc\u00d5\u0001\u0000\u0000\u0000"+
		"\u00cd\u00cf\u0005-\u0000\u0000\u00ce\u00d0\u0005\u0014\u0000\u0000\u00cf"+
		"\u00ce\u0001\u0000\u0000\u0000\u00cf\u00d0\u0001\u0000\u0000\u0000\u00d0"+
		"\u00d1\u0001\u0000\u0000\u0000\u00d1\u00d3\u0003\u0006\u0003\u0000\u00d2"+
		"\u00d4\u0005\u0014\u0000\u0000\u00d3\u00d2\u0001\u0000\u0000\u0000\u00d3"+
		"\u00d4\u0001\u0000\u0000\u0000\u00d4\u00d6\u0001\u0000\u0000\u0000\u00d5"+
		"\u00cd\u0001\u0000\u0000\u0000\u00d5\u00d6\u0001\u0000\u0000\u0000\u00d6"+
		"\u00d8\u0001\u0000\u0000\u0000\u00d7\u00c5\u0001\u0000\u0000\u0000\u00d7"+
		"\u00d8\u0001\u0000\u0000\u0000\u00d8\u00d9\u0001\u0000\u0000\u0000\u00d9"+
		"\u00da\u0005\'\u0000\u0000\u00da\u00ed\u0001\u0000\u0000\u0000\u00db\u00ed"+
		"\u00036\u001b\u0000\u00dc\u00ed\u0003&\u0013\u0000\u00dd\u00ed\u0005\u000e"+
		"\u0000\u0000\u00de\u00df\u0005\f\u0000\u0000\u00df\u00e0\u0005\u0014\u0000"+
		"\u0000\u00e0\u00ed\u0003\u0006\u0003\u0003\u00e1\u00e3\u0003.\u0017\u0000"+
		"\u00e2\u00e4\u0005\u0014\u0000\u0000\u00e3\u00e2\u0001\u0000\u0000\u0000"+
		"\u00e3\u00e4\u0001\u0000\u0000\u0000\u00e4\u00e5\u0001\u0000\u0000\u0000"+
		"\u00e5\u00e7\u0003\u001e\u000f\u0000\u00e6\u00e8\u0005\u0014\u0000\u0000"+
		"\u00e7\u00e6\u0001\u0000\u0000\u0000\u00e7\u00e8\u0001\u0000\u0000\u0000"+
		"\u00e8\u00e9\u0001\u0000\u0000\u0000\u00e9\u00ea\u0003\u0006\u0003\u0000"+
		"\u00ea\u00ed\u0001\u0000\u0000\u0000\u00eb\u00ed\u0003.\u0017\u0000\u00ec"+
		"\u009b\u0001\u0000\u0000\u0000\u00ec\u00b2\u0001\u0000\u0000\u0000\u00ec"+
		"\u00bc\u0001\u0000\u0000\u0000\u00ec\u00db\u0001\u0000\u0000\u0000\u00ec"+
		"\u00dc\u0001\u0000\u0000\u0000\u00ec\u00dd\u0001\u0000\u0000\u0000\u00ec"+
		"\u00de\u0001\u0000\u0000\u0000\u00ec\u00e1\u0001\u0000\u0000\u0000\u00ec"+
		"\u00eb\u0001\u0000\u0000\u0000\u00ed\u00f5\u0001\u0000\u0000\u0000\u00ee"+
		"\u00ef\n\u0007\u0000\u0000\u00ef\u00f0\u0005\u0014\u0000\u0000\u00f0\u00f1"+
		"\u0007\u0001\u0000\u0000\u00f1\u00f2\u0005\u0014\u0000\u0000\u00f2\u00f4"+
		"\u0003\u0006\u0003\b\u00f3\u00ee\u0001\u0000\u0000\u0000\u00f4\u00f7\u0001"+
		"\u0000\u0000\u0000\u00f5\u00f3\u0001\u0000\u0000\u0000\u00f5\u00f6\u0001"+
		"\u0000\u0000\u0000\u00f6\u0007\u0001\u0000\u0000\u0000\u00f7\u00f5\u0001"+
		"\u0000\u0000\u0000\u00f8\u00fb\u0003\n\u0005\u0000\u00f9\u00fb\u0003."+
		"\u0017\u0000\u00fa\u00f8\u0001\u0000\u0000\u0000\u00fa\u00f9\u0001\u0000"+
		"\u0000\u0000\u00fb\u00fd\u0001\u0000\u0000\u0000\u00fc\u00fe\u0005\u0014"+
		"\u0000\u0000\u00fd\u00fc\u0001\u0000\u0000\u0000\u00fd\u00fe\u0001\u0000"+
		"\u0000\u0000\u00fe\u00ff\u0001\u0000\u0000\u0000\u00ff\u0101\u0005A\u0000"+
		"\u0000\u0100\u0102\u0005\u0014\u0000\u0000\u0101\u0100\u0001\u0000\u0000"+
		"\u0000\u0101\u0102\u0001\u0000\u0000\u0000\u0102\u0103\u0001\u0000\u0000"+
		"\u0000\u0103\u0104\u0003\u0004\u0002\u0000\u0104\t\u0001\u0000\u0000\u0000"+
		"\u0105\u0106\u0005\u0001\u0000\u0000\u0106\u0107\u0005\u0014\u0000\u0000"+
		"\u0107\u0108\u0003*\u0015\u0000\u0108\u000b\u0001\u0000\u0000\u0000\u0109"+
		"\u010a\u0005(\u0000\u0000\u010a\u0110\u0003 \u0010\u0000\u010b\u010c\u0005"+
		")\u0000\u0000\u010c\u0110\u0003\u0004\u0002\u0000\u010d\u010e\u0005*\u0000"+
		"\u0000\u010e\u0110\u0003$\u0012\u0000\u010f\u0109\u0001\u0000\u0000\u0000"+
		"\u010f\u010b\u0001\u0000\u0000\u0000\u010f\u010d\u0001\u0000\u0000\u0000"+
		"\u0110\r\u0001\u0000\u0000\u0000\u0111\u0112\u0005\u0007\u0000\u0000\u0112"+
		"\u0113\u0005\u0014\u0000\u0000\u0113\u0115\u0003\u001c\u000e\u0000\u0114"+
		"\u0116\u0005\u0014\u0000\u0000\u0115\u0114\u0001\u0000\u0000\u0000\u0115"+
		"\u0116\u0001\u0000\u0000\u0000\u0116\u0117\u0001\u0000\u0000\u0000\u0117"+
		"\u0118\u0005+\u0000\u0000\u0118\u011a\u0003\u0014\n\u0000\u0119\u011b"+
		"\u0003\u0010\b\u0000\u011a\u0119\u0001\u0000\u0000\u0000\u011a\u011b\u0001"+
		"\u0000\u0000\u0000\u011b\u013d\u0001\u0000\u0000\u0000\u011c\u011d\u0005"+
		"\t\u0000\u0000\u011d\u011e\u0005\u0014\u0000\u0000\u011e\u0127\u0003*"+
		"\u0015\u0000\u011f\u0121\u0005\u0014\u0000\u0000\u0120\u011f\u0001\u0000"+
		"\u0000\u0000\u0120\u0121\u0001\u0000\u0000\u0000\u0121\u0122\u0001\u0000"+
		"\u0000\u0000\u0122\u0124\u0005-\u0000\u0000\u0123\u0125\u0005\u0014\u0000"+
		"\u0000\u0124\u0123\u0001\u0000\u0000\u0000\u0124\u0125\u0001\u0000\u0000"+
		"\u0000\u0125\u0126\u0001\u0000\u0000\u0000\u0126\u0128\u0003*\u0015\u0000"+
		"\u0127\u0120\u0001\u0000\u0000\u0000\u0127\u0128\u0001\u0000\u0000\u0000"+
		"\u0128\u0129\u0001\u0000\u0000\u0000\u0129\u012a\u0005\u0014\u0000\u0000"+
		"\u012a\u012b\u0005\n\u0000\u0000\u012b\u012c\u0005\u0014\u0000\u0000\u012c"+
		"\u012e\u0003\u0018\f\u0000\u012d\u012f\u0005\u0014\u0000\u0000\u012e\u012d"+
		"\u0001\u0000\u0000\u0000\u012e\u012f\u0001\u0000\u0000\u0000\u012f\u0130"+
		"\u0001\u0000\u0000\u0000\u0130\u0131\u0005+\u0000\u0000\u0131\u0132\u0003"+
		"\u0014\n\u0000\u0132\u013d\u0001\u0000\u0000\u0000\u0133\u0134\u0005\r"+
		"\u0000\u0000\u0134\u0135\u0005\u0014\u0000\u0000\u0135\u0137\u0003\u001c"+
		"\u000e\u0000\u0136\u0138\u0005\u0014\u0000\u0000\u0137\u0136\u0001\u0000"+
		"\u0000\u0000\u0137\u0138\u0001\u0000\u0000\u0000\u0138\u0139\u0001\u0000"+
		"\u0000\u0000\u0139\u013a\u0005+\u0000\u0000\u013a\u013b\u0003\u0014\n"+
		"\u0000\u013b\u013d\u0001\u0000\u0000\u0000\u013c\u0111\u0001\u0000\u0000"+
		"\u0000\u013c\u011c\u0001\u0000\u0000\u0000\u013c\u0133\u0001\u0000\u0000"+
		"\u0000\u013d\u000f\u0001\u0000\u0000\u0000\u013e\u0140\u0005\b\u0000\u0000"+
		"\u013f\u0141\u0005\u0014\u0000\u0000\u0140\u013f\u0001\u0000\u0000\u0000"+
		"\u0140\u0141\u0001\u0000\u0000\u0000\u0141\u0142\u0001\u0000\u0000\u0000"+
		"\u0142\u0143\u0005+\u0000\u0000\u0143\u0144\u0003\u0014\n\u0000\u0144"+
		"\u0011\u0001\u0000\u0000\u0000\u0145\u0146\u0005\u0006\u0000\u0000\u0146"+
		"\u0147\u0005\u0014\u0000\u0000\u0147\u0149\u0003*\u0015\u0000\u0148\u014a"+
		"\u0005\u0014\u0000\u0000\u0149\u0148\u0001\u0000\u0000\u0000\u0149\u014a"+
		"\u0001\u0000\u0000\u0000\u014a\u014b\u0001\u0000\u0000\u0000\u014b\u014d"+
		"\u0005&\u0000\u0000\u014c\u014e\u0003\u001a\r\u0000\u014d\u014c\u0001"+
		"\u0000\u0000\u0000\u014d\u014e\u0001\u0000\u0000\u0000\u014e\u014f\u0001"+
		"\u0000\u0000\u0000\u014f\u0151\u0005\'\u0000\u0000\u0150\u0152\u0005\u0014"+
		"\u0000\u0000\u0151\u0150\u0001\u0000\u0000\u0000\u0151\u0152\u0001\u0000"+
		"\u0000\u0000\u0152\u0153\u0001\u0000\u0000\u0000\u0153\u0154\u0005+\u0000"+
		"\u0000\u0154\u0155\u0003\u0014\n\u0000\u0155\u0013\u0001\u0000\u0000\u0000"+
		"\u0156\u015b\u0005O\u0000\u0000\u0157\u0159\u0003\u0016\u000b\u0000\u0158"+
		"\u015a\u0005\u0013\u0000\u0000\u0159\u0158\u0001\u0000\u0000\u0000\u0159"+
		"\u015a\u0001\u0000\u0000\u0000\u015a\u015c\u0001\u0000\u0000\u0000\u015b"+
		"\u0157\u0001\u0000\u0000\u0000\u015c\u015d\u0001\u0000\u0000\u0000\u015d"+
		"\u015b\u0001\u0000\u0000\u0000\u015d\u015e\u0001\u0000\u0000\u0000\u015e"+
		"\u015f\u0001\u0000\u0000\u0000\u015f\u0160\u0005P\u0000\u0000\u0160\u0015"+
		"\u0001\u0000\u0000\u0000\u0161\u0168\u0005\u0011\u0000\u0000\u0162\u0168"+
		"\u0005\u0012\u0000\u0000\u0163\u0164\u0005\u0010\u0000\u0000\u0164\u0165"+
		"\u0005\u0014\u0000\u0000\u0165\u0168\u0003\u0004\u0002\u0000\u0166\u0168"+
		"\u0003\u0002\u0001\u0000\u0167\u0161\u0001\u0000\u0000\u0000\u0167\u0162"+
		"\u0001\u0000\u0000\u0000\u0167\u0163\u0001\u0000\u0000\u0000\u0167\u0166"+
		"\u0001\u0000\u0000\u0000\u0168\u0017\u0001\u0000\u0000\u0000\u0169\u016a"+
		"\u0003\u0004\u0002\u0000\u016a\u0019\u0001\u0000\u0000\u0000\u016b\u0176"+
		"\u0003*\u0015\u0000\u016c\u016e\u0005\u0014\u0000\u0000\u016d\u016c\u0001"+
		"\u0000\u0000\u0000\u016d\u016e\u0001\u0000\u0000\u0000\u016e\u016f\u0001"+
		"\u0000\u0000\u0000\u016f\u0171\u0005-\u0000\u0000\u0170\u0172\u0005\u0014"+
		"\u0000\u0000\u0171\u0170\u0001\u0000\u0000\u0000\u0171\u0172\u0001\u0000"+
		"\u0000\u0000\u0172\u0173\u0001\u0000\u0000\u0000\u0173\u0175\u0003*\u0015"+
		"\u0000\u0174\u016d\u0001\u0000\u0000\u0000\u0175\u0178\u0001\u0000\u0000"+
		"\u0000\u0176\u0174\u0001\u0000\u0000\u0000\u0176\u0177\u0001\u0000\u0000"+
		"\u0000\u0177\u001b\u0001\u0000\u0000\u0000\u0178\u0176\u0001\u0000\u0000"+
		"\u0000\u0179\u017a\u0003\u0004\u0002\u0000\u017a\u001d\u0001\u0000\u0000"+
		"\u0000\u017b\u0190\u0005;\u0000\u0000\u017c\u0190\u0005N\u0000\u0000\u017d"+
		"\u0190\u0005:\u0000\u0000\u017e\u0190\u0005<\u0000\u0000\u017f\u0190\u0005"+
		"9\u0000\u0000\u0180\u0190\u0005@\u0000\u0000\u0181\u0190\u0005B\u0000"+
		"\u0000\u0182\u0190\u0005C\u0000\u0000\u0183\u0190\u0005E\u0000\u0000\u0184"+
		"\u0190\u0005D\u0000\u0000\u0185\u0190\u0005F\u0000\u0000\u0186\u0190\u0005"+
		"G\u0000\u0000\u0187\u0190\u0005H\u0000\u0000\u0188\u0190\u00057\u0000"+
		"\u0000\u0189\u018a\u0005I\u0000\u0000\u018a\u0190\u0005=\u0000\u0000\u018b"+
		"\u0190\u0005>\u0000\u0000\u018c\u0190\u0005?\u0000\u0000\u018d\u0190\u0005"+
		")\u0000\u0000\u018e\u0190\u00052\u0000\u0000\u018f\u017b\u0001\u0000\u0000"+
		"\u0000\u018f\u017c\u0001\u0000\u0000\u0000\u018f\u017d\u0001\u0000\u0000"+
		"\u0000\u018f\u017e\u0001\u0000\u0000\u0000\u018f\u017f\u0001\u0000\u0000"+
		"\u0000\u018f\u0180\u0001\u0000\u0000\u0000\u018f\u0181\u0001\u0000\u0000"+
		"\u0000\u018f\u0182\u0001\u0000\u0000\u0000\u018f\u0183\u0001\u0000\u0000"+
		"\u0000\u018f\u0184\u0001\u0000\u0000\u0000\u018f\u0185\u0001\u0000\u0000"+
		"\u0000\u018f\u0186\u0001\u0000\u0000\u0000\u018f\u0187\u0001\u0000\u0000"+
		"\u0000\u018f\u0188\u0001\u0000\u0000\u0000\u018f\u0189\u0001\u0000\u0000"+
		"\u0000\u018f\u018b\u0001\u0000\u0000\u0000\u018f\u018c\u0001\u0000\u0000"+
		"\u0000\u018f\u018d\u0001\u0000\u0000\u0000\u018f\u018e\u0001\u0000\u0000"+
		"\u0000\u0190\u001f\u0001\u0000\u0000\u0000\u0191\u0193\u0003*\u0015\u0000"+
		"\u0192\u0194\u0005\u0014\u0000\u0000\u0193\u0192\u0001\u0000\u0000\u0000"+
		"\u0193\u0194\u0001\u0000\u0000\u0000\u0194\u0195\u0001\u0000\u0000\u0000"+
		"\u0195\u0197\u0005&\u0000\u0000\u0196\u0198\u0005\u0014\u0000\u0000\u0197"+
		"\u0196\u0001\u0000\u0000\u0000\u0197\u0198\u0001\u0000\u0000\u0000\u0198"+
		"\u019c\u0001\u0000\u0000\u0000\u0199\u019b\u0003\"\u0011\u0000\u019a\u0199"+
		"\u0001\u0000\u0000\u0000\u019b\u019e\u0001\u0000\u0000\u0000\u019c\u019a"+
		"\u0001\u0000\u0000\u0000\u019c\u019d\u0001\u0000\u0000\u0000\u019d\u019f"+
		"\u0001\u0000\u0000\u0000\u019e\u019c\u0001\u0000\u0000\u0000\u019f\u01a0"+
		"\u0005\'\u0000\u0000\u01a0!\u0001\u0000\u0000\u0000\u01a1\u01ad\u0003"+
		"&\u0013\u0000\u01a2\u01ad\u00036\u001b\u0000\u01a3\u01ad\u00030\u0018"+
		"\u0000\u01a4\u01a8\u0005&\u0000\u0000\u01a5\u01a7\u0003\"\u0011\u0000"+
		"\u01a6\u01a5\u0001\u0000\u0000\u0000\u01a7\u01aa\u0001\u0000\u0000\u0000"+
		"\u01a8\u01a6\u0001\u0000\u0000\u0000\u01a8\u01a9\u0001\u0000\u0000\u0000"+
		"\u01a9\u01ab\u0001\u0000\u0000\u0000\u01aa\u01a8\u0001\u0000\u0000\u0000"+
		"\u01ab\u01ad\u0005\'\u0000\u0000\u01ac\u01a1\u0001\u0000\u0000\u0000\u01ac"+
		"\u01a2\u0001\u0000\u0000\u0000\u01ac\u01a3\u0001\u0000\u0000\u0000\u01ac"+
		"\u01a4\u0001\u0000\u0000\u0000\u01ad\u01ae\u0001\u0000\u0000\u0000\u01ae"+
		"\u01ac\u0001\u0000\u0000\u0000\u01ae\u01af\u0001\u0000\u0000\u0000\u01af"+
		"#\u0001\u0000\u0000\u0000\u01b0\u01b8\u0003&\u0013\u0000\u01b1\u01b8\u0003"+
		"6\u001b\u0000\u01b2\u01b8\u00030\u0018\u0000\u01b3\u01b4\u0005&\u0000"+
		"\u0000\u01b4\u01b5\u0003$\u0012\u0000\u01b5\u01b6\u0005\'\u0000\u0000"+
		"\u01b6\u01b8\u0001\u0000\u0000\u0000\u01b7\u01b0\u0001\u0000\u0000\u0000"+
		"\u01b7\u01b1\u0001\u0000\u0000\u0000\u01b7\u01b2\u0001\u0000\u0000\u0000"+
		"\u01b7\u01b3\u0001\u0000\u0000\u0000\u01b8\u01bb\u0001\u0000\u0000\u0000"+
		"\u01b9\u01b7\u0001\u0000\u0000\u0000\u01b9\u01ba\u0001\u0000\u0000\u0000"+
		"\u01ba%\u0001\u0000\u0000\u0000\u01bb\u01b9\u0001\u0000\u0000\u0000\u01bc"+
		"\u01bd\u0007\u0002\u0000\u0000\u01bd\u01be\u00051\u0000\u0000\u01be\u01c0"+
		"\u0003*\u0015\u0000\u01bf\u01c1\u0005(\u0000\u0000\u01c0\u01bf\u0001\u0000"+
		"\u0000\u0000\u01c0\u01c1\u0001\u0000\u0000\u0000\u01c1\u01d8\u0001\u0000"+
		"\u0000\u0000\u01c2\u01d8\u0005\u001e\u0000\u0000\u01c3\u01c4\u0005\u001d"+
		"\u0000\u0000\u01c4\u01c6\u00053\u0000\u0000\u01c5\u01c7\u0005\u0014\u0000"+
		"\u0000\u01c6\u01c5\u0001\u0000\u0000\u0000\u01c6\u01c7\u0001\u0000\u0000"+
		"\u0000\u01c7\u01c8\u0001\u0000\u0000\u0000\u01c8\u01d1\u0003(\u0014\u0000"+
		"\u01c9\u01cb\u0005\u0014\u0000\u0000\u01ca\u01c9\u0001\u0000\u0000\u0000"+
		"\u01ca\u01cb\u0001\u0000\u0000\u0000\u01cb\u01cc\u0001\u0000\u0000\u0000"+
		"\u01cc\u01ce\u0005%\u0000\u0000\u01cd\u01cf\u0005\u0014\u0000\u0000\u01ce"+
		"\u01cd\u0001\u0000\u0000\u0000\u01ce\u01cf\u0001\u0000\u0000\u0000\u01cf"+
		"\u01d0\u0001\u0000\u0000\u0000\u01d0\u01d2\u0003(\u0014\u0000\u01d1\u01ca"+
		"\u0001\u0000\u0000\u0000\u01d1\u01d2\u0001\u0000\u0000\u0000\u01d2\u01d3"+
		"\u0001\u0000\u0000\u0000\u01d3\u01d5\u00054\u0000\u0000\u01d4\u01d6\u0005"+
		"(\u0000\u0000\u01d5\u01d4\u0001\u0000\u0000\u0000\u01d5\u01d6\u0001\u0000"+
		"\u0000\u0000\u01d6\u01d8\u0001\u0000\u0000\u0000\u01d7\u01bc\u0001\u0000"+
		"\u0000\u0000\u01d7\u01c2\u0001\u0000\u0000\u0000\u01d7\u01c3\u0001\u0000"+
		"\u0000\u0000\u01d8\'\u0001\u0000\u0000\u0000\u01d9\u01db\u0005N\u0000"+
		"\u0000\u01da\u01d9\u0001\u0000\u0000\u0000\u01da\u01db\u0001\u0000\u0000"+
		"\u0000\u01db\u01dc\u0001\u0000\u0000\u0000\u01dc\u01dd\u0003\u0004\u0002"+
		"\u0000\u01dd)\u0001\u0000\u0000\u0000\u01de\u01e4\u0005\u0018\u0000\u0000"+
		"\u01df\u01e4\u0005M\u0000\u0000\u01e0\u01e1\u00034\u001a\u0000\u01e1\u01e2"+
		"\u0005M\u0000\u0000\u01e2\u01e4\u0001\u0000\u0000\u0000\u01e3\u01de\u0001"+
		"\u0000\u0000\u0000\u01e3\u01df\u0001\u0000\u0000\u0000\u01e3\u01e0\u0001"+
		"\u0000\u0000\u0000\u01e4\u01eb\u0001\u0000\u0000\u0000\u01e5\u01ea\u0005"+
		"\u0018\u0000\u0000\u01e6\u01ea\u0005\u0016\u0000\u0000\u01e7\u01ea\u0005"+
		"M\u0000\u0000\u01e8\u01ea\u00034\u001a\u0000\u01e9\u01e5\u0001\u0000\u0000"+
		"\u0000\u01e9\u01e6\u0001\u0000\u0000\u0000\u01e9\u01e7\u0001\u0000\u0000"+
		"\u0000\u01e9\u01e8\u0001\u0000\u0000\u0000\u01ea\u01ed\u0001\u0000\u0000"+
		"\u0000\u01eb\u01e9\u0001\u0000\u0000\u0000\u01eb\u01ec\u0001\u0000\u0000"+
		"\u0000\u01ec+\u0001\u0000\u0000\u0000\u01ed\u01eb\u0001\u0000\u0000\u0000"+
		"\u01ee\u01ef\u0007\u0003\u0000\u0000\u01ef-\u0001\u0000\u0000\u0000\u01f0"+
		"\u01f1\u0006\u0017\uffff\uffff\u0000\u01f1\u01f3\u0003*\u0015\u0000\u01f2"+
		"\u01f4\u0005(\u0000\u0000\u01f3\u01f2\u0001\u0000\u0000\u0000\u01f3\u01f4"+
		"\u0001\u0000\u0000\u0000\u01f4\u023d\u0001\u0000\u0000\u0000\u01f5\u01f7"+
		"\u0005N\u0000\u0000\u01f6\u01f5\u0001\u0000\u0000\u0000\u01f6\u01f7\u0001"+
		"\u0000\u0000\u0000\u01f7\u01f8\u0001\u0000\u0000\u0000\u01f8\u023d\u0003"+
		",\u0016\u0000\u01f9\u023d\u0005\u000e\u0000\u0000\u01fa\u023d\u0003&\u0013"+
		"\u0000\u01fb\u01fd\u00053\u0000\u0000\u01fc\u01fe\u0005\u0014\u0000\u0000"+
		"\u01fd\u01fc\u0001\u0000\u0000\u0000\u01fd\u01fe\u0001\u0000\u0000\u0000"+
		"\u01fe\u0200\u0001\u0000\u0000\u0000\u01ff\u0201\u0003.\u0017\u0000\u0200"+
		"\u01ff\u0001\u0000\u0000\u0000\u0200\u0201\u0001\u0000\u0000\u0000\u0201"+
		"\u020c\u0001\u0000\u0000\u0000\u0202\u0204\u0005\u0014\u0000\u0000\u0203"+
		"\u0202\u0001\u0000\u0000\u0000\u0203\u0204\u0001\u0000\u0000\u0000\u0204"+
		"\u0205\u0001\u0000\u0000\u0000\u0205\u0207\u0005-\u0000\u0000\u0206\u0208"+
		"\u0005\u0014\u0000\u0000\u0207\u0206\u0001\u0000\u0000\u0000\u0207\u0208"+
		"\u0001\u0000\u0000\u0000\u0208\u0209\u0001\u0000\u0000\u0000\u0209\u020b"+
		"\u0003.\u0017\u0000\u020a\u0203\u0001\u0000\u0000\u0000\u020b\u020e\u0001"+
		"\u0000\u0000\u0000\u020c\u020a\u0001\u0000\u0000\u0000\u020c\u020d\u0001"+
		"\u0000\u0000\u0000\u020d\u0210\u0001\u0000\u0000\u0000\u020e\u020c\u0001"+
		"\u0000\u0000\u0000\u020f\u0211\u0005\u0014\u0000\u0000\u0210\u020f\u0001"+
		"\u0000\u0000\u0000\u0210\u0211\u0001\u0000\u0000\u0000\u0211\u0212\u0001"+
		"\u0000\u0000\u0000\u0212\u023d\u00054\u0000\u0000\u0213\u0215\u00055\u0000"+
		"\u0000\u0214\u0216\u0005\u0014\u0000\u0000\u0215\u0214\u0001\u0000\u0000"+
		"\u0000\u0215\u0216\u0001\u0000\u0000\u0000\u0216\u0233\u0001\u0000\u0000"+
		"\u0000\u0217\u0219\u0005\u001f\u0000\u0000\u0218\u021a\u0005\u0014\u0000"+
		"\u0000\u0219\u0218\u0001\u0000\u0000\u0000\u0219\u021a\u0001\u0000\u0000"+
		"\u0000\u021a\u021b\u0001\u0000\u0000\u0000\u021b\u021d\u0005+\u0000\u0000"+
		"\u021c\u021e\u0005\u0014\u0000\u0000\u021d\u021c\u0001\u0000\u0000\u0000"+
		"\u021d\u021e\u0001\u0000\u0000\u0000\u021e\u021f\u0001\u0000\u0000\u0000"+
		"\u021f\u0221\u0003.\u0017\u0000\u0220\u0222\u0005\u0014\u0000\u0000\u0221"+
		"\u0220\u0001\u0000\u0000\u0000\u0221\u0222\u0001\u0000\u0000\u0000\u0222"+
		"\u0223\u0001\u0000\u0000\u0000\u0223\u0225\u0005-\u0000\u0000\u0224\u0226"+
		"\u0005\u0014\u0000\u0000\u0225\u0224\u0001\u0000\u0000\u0000\u0225\u0226"+
		"\u0001\u0000\u0000\u0000\u0226\u0227\u0001\u0000\u0000\u0000\u0227\u0229"+
		"\u0005\u001f\u0000\u0000\u0228\u022a\u0005\u0014\u0000\u0000\u0229\u0228"+
		"\u0001\u0000\u0000\u0000\u0229\u022a\u0001\u0000\u0000\u0000\u022a\u022b"+
		"\u0001\u0000\u0000\u0000\u022b\u022d\u0005+\u0000\u0000\u022c\u022e\u0005"+
		"\u0014\u0000\u0000\u022d\u022c\u0001\u0000\u0000\u0000\u022d\u022e\u0001"+
		"\u0000\u0000\u0000\u022e\u022f\u0001\u0000\u0000\u0000\u022f\u0230\u0003"+
		".\u0017\u0000\u0230\u0232\u0001\u0000\u0000\u0000\u0231\u0217\u0001\u0000"+
		"\u0000\u0000\u0232\u0235\u0001\u0000\u0000\u0000\u0233\u0231\u0001\u0000"+
		"\u0000\u0000\u0233\u0234\u0001\u0000\u0000\u0000\u0234\u0237\u0001\u0000"+
		"\u0000\u0000\u0235\u0233\u0001\u0000\u0000\u0000\u0236\u0238\u0005\u0014"+
		"\u0000\u0000\u0237\u0236\u0001\u0000\u0000\u0000\u0237\u0238\u0001\u0000"+
		"\u0000\u0000\u0238\u0239\u0001\u0000\u0000\u0000\u0239\u023d\u00056\u0000"+
		"\u0000\u023a\u023d\u0005\u001f\u0000\u0000\u023b\u023d\u0005 \u0000\u0000"+
		"\u023c\u01f0\u0001\u0000\u0000\u0000\u023c\u01f6\u0001\u0000\u0000\u0000"+
		"\u023c\u01f9\u0001\u0000\u0000\u0000\u023c\u01fa\u0001\u0000\u0000\u0000"+
		"\u023c\u01fb\u0001\u0000\u0000\u0000\u023c\u0213\u0001\u0000\u0000\u0000"+
		"\u023c\u023a\u0001\u0000\u0000\u0000\u023c\u023b\u0001\u0000\u0000\u0000"+
		"\u023d\u0276\u0001\u0000\u0000\u0000\u023e\u023f\n\b\u0000\u0000\u023f"+
		"\u0240\u00051\u0000\u0000\u0240\u0275\u0003*\u0015\u0000\u0241\u0242\n"+
		"\u0007\u0000\u0000\u0242\u0244\u00053\u0000\u0000\u0243\u0245\u0005\u0014"+
		"\u0000\u0000\u0244\u0243\u0001\u0000\u0000\u0000\u0244\u0245\u0001\u0000"+
		"\u0000\u0000\u0245\u0246\u0001\u0000\u0000\u0000\u0246\u0248\u0003(\u0014"+
		"\u0000\u0247\u0249\u0005\u0014\u0000\u0000\u0248\u0247\u0001\u0000\u0000"+
		"\u0000\u0248\u0249\u0001\u0000\u0000\u0000\u0249\u024a\u0001\u0000\u0000"+
		"\u0000\u024a\u024b\u00054\u0000\u0000\u024b\u0275\u0001\u0000\u0000\u0000"+
		"\u024c\u024d\n\u0006\u0000\u0000\u024d\u024f\u00053\u0000\u0000\u024e"+
		"\u0250\u0005\u0014\u0000\u0000\u024f\u024e\u0001\u0000\u0000\u0000\u024f"+
		"\u0250\u0001\u0000\u0000\u0000\u0250\u0251\u0001\u0000\u0000\u0000\u0251"+
		"\u0253\u0003(\u0014\u0000\u0252\u0254\u0005\u0014\u0000\u0000\u0253\u0252"+
		"\u0001\u0000\u0000\u0000\u0253\u0254\u0001\u0000\u0000\u0000\u0254\u0255"+
		"\u0001\u0000\u0000\u0000\u0255\u0257\u0005+\u0000\u0000\u0256\u0258\u0005"+
		"\u0014\u0000\u0000\u0257\u0256\u0001\u0000\u0000\u0000\u0257\u0258\u0001"+
		"\u0000\u0000\u0000\u0258\u025a\u0001\u0000\u0000\u0000\u0259\u025b\u0003"+
		"(\u0014\u0000\u025a\u0259\u0001\u0000\u0000\u0000\u025a\u025b\u0001\u0000"+
		"\u0000\u0000\u025b\u025d\u0001\u0000\u0000\u0000\u025c\u025e\u0005\u0014"+
		"\u0000\u0000\u025d\u025c\u0001\u0000\u0000\u0000\u025d\u025e\u0001\u0000"+
		"\u0000\u0000\u025e\u025f\u0001\u0000\u0000\u0000\u025f\u0260\u00054\u0000"+
		"\u0000\u0260\u0275\u0001\u0000\u0000\u0000\u0261\u0262\n\u0005\u0000\u0000"+
		"\u0262\u0264\u00053\u0000\u0000\u0263\u0265\u0005\u0014\u0000\u0000\u0264"+
		"\u0263\u0001\u0000\u0000\u0000\u0264\u0265\u0001\u0000\u0000\u0000\u0265"+
		"\u0266\u0001\u0000\u0000\u0000\u0266\u0268\u0003(\u0014\u0000\u0267\u0269"+
		"\u0005\u0014\u0000\u0000\u0268\u0267\u0001\u0000\u0000\u0000\u0268\u0269"+
		"\u0001\u0000\u0000\u0000\u0269\u026a\u0001\u0000\u0000\u0000\u026a\u026c"+
		"\u0005%\u0000\u0000\u026b\u026d\u0005\u0014\u0000\u0000\u026c\u026b\u0001"+
		"\u0000\u0000\u0000\u026c\u026d\u0001\u0000\u0000\u0000\u026d\u026e\u0001"+
		"\u0000\u0000\u0000\u026e\u0270\u0003(\u0014\u0000\u026f\u0271\u0005\u0014"+
		"\u0000\u0000\u0270\u026f\u0001\u0000\u0000\u0000\u0270\u0271\u0001\u0000"+
		"\u0000\u0000\u0271\u0272\u0001\u0000\u0000\u0000\u0272\u0273\u00054\u0000"+
		"\u0000\u0273\u0275\u0001\u0000\u0000\u0000\u0274\u023e\u0001\u0000\u0000"+
		"\u0000\u0274\u0241\u0001\u0000\u0000\u0000\u0274\u024c\u0001\u0000\u0000"+
		"\u0000\u0274\u0261\u0001\u0000\u0000\u0000\u0275\u0278\u0001\u0000\u0000"+
		"\u0000\u0276\u0274\u0001\u0000\u0000\u0000\u0276\u0277\u0001\u0000\u0000"+
		"\u0000\u0277/\u0001\u0000\u0000\u0000\u0278\u0276\u0001\u0000\u0000\u0000"+
		"\u0279\u027c\u00032\u0019\u0000\u027a\u027c\u0005\u0013\u0000\u0000\u027b"+
		"\u0279\u0001\u0000\u0000\u0000\u027b\u027a\u0001\u0000\u0000\u0000\u027c"+
		"1\u0001\u0000\u0000\u0000\u027d\u0289\u0005\u0018\u0000\u0000\u027e\u0289"+
		"\u0005\u0016\u0000\u0000\u027f\u0289\u0003>\u001f\u0000\u0280\u0289\u0005"+
		"\u001f\u0000\u0000\u0281\u0289\u0005 \u0000\u0000\u0282\u0289\u0005\u0014"+
		"\u0000\u0000\u0283\u0284\u0005&\u0000\u0000\u0284\u0285\u00030\u0018\u0000"+
		"\u0285\u0286\u0005\'\u0000\u0000\u0286\u0289\u0001\u0000\u0000\u0000\u0287"+
		"\u0289\u00034\u001a\u0000\u0288\u027d\u0001\u0000\u0000\u0000\u0288\u027e"+
		"\u0001\u0000\u0000\u0000\u0288\u027f\u0001\u0000\u0000\u0000\u0288\u0280"+
		"\u0001\u0000\u0000\u0000\u0288\u0281\u0001\u0000\u0000\u0000\u0288\u0282"+
		"\u0001\u0000\u0000\u0000\u0288\u0283\u0001\u0000\u0000\u0000\u0288\u0287"+
		"\u0001\u0000\u0000\u0000\u02893\u0001\u0000\u0000\u0000\u028a\u028b\u0007"+
		"\u0004\u0000\u0000\u028b5\u0001\u0000\u0000\u0000\u028c\u0290\u00038\u001c"+
		"\u0000\u028d\u0290\u0003:\u001d\u0000\u028e\u0290\u0003<\u001e\u0000\u028f"+
		"\u028c\u0001\u0000\u0000\u0000\u028f\u028d\u0001\u0000\u0000\u0000\u028f"+
		"\u028e\u0001\u0000\u0000\u0000\u02907\u0001\u0000\u0000\u0000\u0291\u0292"+
		"\u0005)\u0000\u0000\u0292\u0293\u0005&\u0000\u0000\u0293\u0294\u0003\u0004"+
		"\u0002\u0000\u0294\u0295\u0005\'\u0000\u0000\u02959\u0001\u0000\u0000"+
		"\u0000\u0296\u0297\u0005*\u0000\u0000\u0297\u0298\u0005&\u0000\u0000\u0298"+
		"\u0299\u0003$\u0012\u0000\u0299\u029a\u0005\'\u0000\u0000\u029a;\u0001"+
		"\u0000\u0000\u0000\u029b\u029c\u0005(\u0000\u0000\u029c\u029d\u0005&\u0000"+
		"\u0000\u029d\u029e\u0003\"\u0011\u0000\u029e\u029f\u0005\'\u0000\u0000"+
		"\u029f=\u0001\u0000\u0000\u0000\u02a0\u02a1\u0007\u0005\u0000\u0000\u02a1"+
		"?\u0001\u0000\u0000\u0000nCMPRX[dmv\u007f\u0084\u0089\u0090\u0095\u0099"+
		"\u009e\u00a2\u00a6\u00aa\u00ae\u00b4\u00b8\u00bf\u00c3\u00c7\u00cb\u00cf"+
		"\u00d3\u00d5\u00d7\u00e3\u00e7\u00ec\u00f5\u00fa\u00fd\u0101\u010f\u0115"+
		"\u011a\u0120\u0124\u0127\u012e\u0137\u013c\u0140\u0149\u014d\u0151\u0159"+
		"\u015d\u0167\u016d\u0171\u0176\u018f\u0193\u0197\u019c\u01a8\u01ac\u01ae"+
		"\u01b7\u01b9\u01c0\u01c6\u01ca\u01ce\u01d1\u01d5\u01d7\u01da\u01e3\u01e9"+
		"\u01eb\u01f3\u01f6\u01fd\u0200\u0203\u0207\u020c\u0210\u0215\u0219\u021d"+
		"\u0221\u0225\u0229\u022d\u0233\u0237\u023c\u0244\u0248\u024f\u0253\u0257"+
		"\u025a\u025d\u0264\u0268\u026c\u0270\u0274\u0276\u027b\u0288\u028f";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}