// Generated from /workspaces/dAngr/src/dAngr/cli/grammar/ranges.g4 by ANTLR 4.13.1
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue"})
public class rangesParser extends Parser {
	static { RuntimeMetaData.checkVersion("4.13.1", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		HEX_NUMBERS=1, NUMBERS=2, NUMBER=3, LETTERS=4, LETTER=5, SYM_DB=6, REG_DB=7, 
		VARS_DB=8, MEM_DB=9, STATE=10, STRING=11, BINARY_STRING=12, ESCAPED_QUOTE=13, 
		ESCAPED_SINGLE_QUOTE=14, SESC_SEQ=15, ESC_SEQ=16, ARROW=17, LPAREN=18, 
		RPAREN=19, BANG=20, AMP=21, DOLLAR=22, COLON=23, SCOLON=24, COMMA=25, 
		QUOTE=26, SQUOTE=27, AT=28, DOT=29, BAR=30, BRA=31, KET=32, BRACE=33, 
		KETCE=34, HAT=35, HASH=36, PERC=37, MUL=38, ADD=39, DIV=40, FLOORDIV=41, 
		LSHIFT=42, RSHIFT=43, POW=44, ASSIGN=45, EQ=46, NEQ=47, LT=48, GT=49, 
		LE=50, GE=51, AND=52, OR=53, QMARK=54, TILDE=55, TICK=56, UNDERSCORE=57, 
		DASH=58, NEWLINE=59, WS=60;
	public static final int
		RULE_expression = 0, RULE_range = 1, RULE_dangr_range = 2, RULE_bash_range = 3, 
		RULE_python_range = 4, RULE_bash_content = 5, RULE_py_content = 6, RULE_anything = 7, 
		RULE_symbol = 8;
	private static String[] makeRuleNames() {
		return new String[] {
			"expression", "range", "dangr_range", "bash_range", "python_range", "bash_content", 
			"py_content", "anything", "symbol"
		};
	}
	public static final String[] ruleNames = makeRuleNames();

	private static String[] makeLiteralNames() {
		return new String[] {
			null, null, null, null, null, null, "'&sym'", "'&reg'", "'&vars'", "'&mem'", 
			"'&state'", null, null, null, null, null, null, "'->'", "'('", "')'", 
			"'!'", "'&'", "'$'", "':'", "';'", "','", "'\"'", "'''", "'@'", "'.'", 
			"'|'", "'['", "']'", "'{'", "'}'", "'^'", "'#'", "'%'", "'*'", "'+'", 
			"'/'", "'//'", "'<<'", "'>>'", "'**'", "'='", "'=='", "'!='", "'<'", 
			"'>'", "'<='", "'>='", "'&&'", "'||'", "'?'", "'~'", "'`'", "'_'", "'-'"
		};
	}
	private static final String[] _LITERAL_NAMES = makeLiteralNames();
	private static String[] makeSymbolicNames() {
		return new String[] {
			null, "HEX_NUMBERS", "NUMBERS", "NUMBER", "LETTERS", "LETTER", "SYM_DB", 
			"REG_DB", "VARS_DB", "MEM_DB", "STATE", "STRING", "BINARY_STRING", "ESCAPED_QUOTE", 
			"ESCAPED_SINGLE_QUOTE", "SESC_SEQ", "ESC_SEQ", "ARROW", "LPAREN", "RPAREN", 
			"BANG", "AMP", "DOLLAR", "COLON", "SCOLON", "COMMA", "QUOTE", "SQUOTE", 
			"AT", "DOT", "BAR", "BRA", "KET", "BRACE", "KETCE", "HAT", "HASH", "PERC", 
			"MUL", "ADD", "DIV", "FLOORDIV", "LSHIFT", "RSHIFT", "POW", "ASSIGN", 
			"EQ", "NEQ", "LT", "GT", "LE", "GE", "AND", "OR", "QMARK", "TILDE", "TICK", 
			"UNDERSCORE", "DASH", "NEWLINE", "WS"
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
	public String getGrammarFileName() { return "ranges.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public rangesParser(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionContext extends ParserRuleContext {
		public RangeContext range() {
			return getRuleContext(RangeContext.class,0);
		}
		public ExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_expression; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterExpression(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitExpression(this);
		}
	}

	public final ExpressionContext expression() throws RecognitionException {
		ExpressionContext _localctx = new ExpressionContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_expression);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(18);
			range();
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
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterRange(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitRange(this);
		}
	}

	public final RangeContext range() throws RecognitionException {
		RangeContext _localctx = new RangeContext(_ctx, getState());
		enterRule(_localctx, 2, RULE_range);
		try {
			setState(23);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case AMP:
				enterOuterAlt(_localctx, 1);
				{
				setState(20);
				dangr_range();
				}
				break;
			case DOLLAR:
				enterOuterAlt(_localctx, 2);
				{
				setState(21);
				bash_range();
				}
				break;
			case BANG:
				enterOuterAlt(_localctx, 3);
				{
				setState(22);
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
		public TerminalNode AMP() { return getToken(rangesParser.AMP, 0); }
		public TerminalNode LPAREN() { return getToken(rangesParser.LPAREN, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(rangesParser.RPAREN, 0); }
		public Dangr_rangeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_dangr_range; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterDangr_range(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitDangr_range(this);
		}
	}

	public final Dangr_rangeContext dangr_range() throws RecognitionException {
		Dangr_rangeContext _localctx = new Dangr_rangeContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_dangr_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(25);
			match(AMP);
			setState(26);
			match(LPAREN);
			setState(27);
			expression();
			setState(28);
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
		public TerminalNode DOLLAR() { return getToken(rangesParser.DOLLAR, 0); }
		public TerminalNode LPAREN() { return getToken(rangesParser.LPAREN, 0); }
		public Bash_contentContext bash_content() {
			return getRuleContext(Bash_contentContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(rangesParser.RPAREN, 0); }
		public Bash_rangeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_bash_range; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterBash_range(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitBash_range(this);
		}
	}

	public final Bash_rangeContext bash_range() throws RecognitionException {
		Bash_rangeContext _localctx = new Bash_rangeContext(_ctx, getState());
		enterRule(_localctx, 6, RULE_bash_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(30);
			match(DOLLAR);
			setState(31);
			match(LPAREN);
			setState(32);
			bash_content();
			setState(33);
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
		public TerminalNode BANG() { return getToken(rangesParser.BANG, 0); }
		public TerminalNode LPAREN() { return getToken(rangesParser.LPAREN, 0); }
		public Py_contentContext py_content() {
			return getRuleContext(Py_contentContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(rangesParser.RPAREN, 0); }
		public Python_rangeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_python_range; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterPython_range(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitPython_range(this);
		}
	}

	public final Python_rangeContext python_range() throws RecognitionException {
		Python_rangeContext _localctx = new Python_rangeContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_python_range);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(35);
			match(BANG);
			setState(36);
			match(LPAREN);
			setState(37);
			py_content();
			setState(38);
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
	public static class Bash_contentContext extends ParserRuleContext {
		public AnythingContext anything() {
			return getRuleContext(AnythingContext.class,0);
		}
		public Bash_contentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_bash_content; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterBash_content(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitBash_content(this);
		}
	}

	public final Bash_contentContext bash_content() throws RecognitionException {
		Bash_contentContext _localctx = new Bash_contentContext(_ctx, getState());
		enterRule(_localctx, 10, RULE_bash_content);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(40);
			anything();
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
		public AnythingContext anything() {
			return getRuleContext(AnythingContext.class,0);
		}
		public Py_contentContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_py_content; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterPy_content(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitPy_content(this);
		}
	}

	public final Py_contentContext py_content() throws RecognitionException {
		Py_contentContext _localctx = new Py_contentContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_py_content);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(42);
			anything();
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
	public static class AnythingContext extends ParserRuleContext {
		public TerminalNode LETTERS() { return getToken(rangesParser.LETTERS, 0); }
		public TerminalNode NUMBERS() { return getToken(rangesParser.NUMBERS, 0); }
		public SymbolContext symbol() {
			return getRuleContext(SymbolContext.class,0);
		}
		public TerminalNode STRING() { return getToken(rangesParser.STRING, 0); }
		public TerminalNode BINARY_STRING() { return getToken(rangesParser.BINARY_STRING, 0); }
		public TerminalNode WS() { return getToken(rangesParser.WS, 0); }
		public TerminalNode LPAREN() { return getToken(rangesParser.LPAREN, 0); }
		public AnythingContext anything() {
			return getRuleContext(AnythingContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(rangesParser.RPAREN, 0); }
		public AnythingContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_anything; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterAnything(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitAnything(this);
		}
	}

	public final AnythingContext anything() throws RecognitionException {
		AnythingContext _localctx = new AnythingContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_anything);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(54);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,1,_ctx) ) {
			case 1:
				{
				setState(44);
				match(LETTERS);
				}
				break;
			case 2:
				{
				setState(45);
				match(NUMBERS);
				}
				break;
			case 3:
				{
				setState(46);
				symbol();
				}
				break;
			case 4:
				{
				setState(47);
				match(STRING);
				}
				break;
			case 5:
				{
				setState(48);
				match(BINARY_STRING);
				}
				break;
			case 6:
				{
				setState(49);
				match(WS);
				}
				break;
			case 7:
				{
				setState(50);
				match(LPAREN);
				setState(51);
				anything();
				setState(52);
				match(RPAREN);
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
	public static class SymbolContext extends ParserRuleContext {
		public TerminalNode WS() { return getToken(rangesParser.WS, 0); }
		public TerminalNode BANG() { return getToken(rangesParser.BANG, 0); }
		public TerminalNode AMP() { return getToken(rangesParser.AMP, 0); }
		public TerminalNode DOLLAR() { return getToken(rangesParser.DOLLAR, 0); }
		public TerminalNode COLON() { return getToken(rangesParser.COLON, 0); }
		public TerminalNode SCOLON() { return getToken(rangesParser.SCOLON, 0); }
		public TerminalNode COMMA() { return getToken(rangesParser.COMMA, 0); }
		public TerminalNode QUOTE() { return getToken(rangesParser.QUOTE, 0); }
		public TerminalNode SQUOTE() { return getToken(rangesParser.SQUOTE, 0); }
		public TerminalNode AT() { return getToken(rangesParser.AT, 0); }
		public TerminalNode DOT() { return getToken(rangesParser.DOT, 0); }
		public TerminalNode BAR() { return getToken(rangesParser.BAR, 0); }
		public TerminalNode BRA() { return getToken(rangesParser.BRA, 0); }
		public TerminalNode KET() { return getToken(rangesParser.KET, 0); }
		public TerminalNode BRACE() { return getToken(rangesParser.BRACE, 0); }
		public TerminalNode KETCE() { return getToken(rangesParser.KETCE, 0); }
		public TerminalNode HAT() { return getToken(rangesParser.HAT, 0); }
		public TerminalNode HASH() { return getToken(rangesParser.HASH, 0); }
		public TerminalNode PERC() { return getToken(rangesParser.PERC, 0); }
		public TerminalNode MUL() { return getToken(rangesParser.MUL, 0); }
		public TerminalNode ADD() { return getToken(rangesParser.ADD, 0); }
		public TerminalNode DIV() { return getToken(rangesParser.DIV, 0); }
		public TerminalNode POW() { return getToken(rangesParser.POW, 0); }
		public TerminalNode ASSIGN() { return getToken(rangesParser.ASSIGN, 0); }
		public TerminalNode EQ() { return getToken(rangesParser.EQ, 0); }
		public TerminalNode NEQ() { return getToken(rangesParser.NEQ, 0); }
		public TerminalNode LT() { return getToken(rangesParser.LT, 0); }
		public TerminalNode GT() { return getToken(rangesParser.GT, 0); }
		public TerminalNode LE() { return getToken(rangesParser.LE, 0); }
		public TerminalNode GE() { return getToken(rangesParser.GE, 0); }
		public TerminalNode AND() { return getToken(rangesParser.AND, 0); }
		public TerminalNode OR() { return getToken(rangesParser.OR, 0); }
		public TerminalNode QMARK() { return getToken(rangesParser.QMARK, 0); }
		public TerminalNode TILDE() { return getToken(rangesParser.TILDE, 0); }
		public TerminalNode TICK() { return getToken(rangesParser.TICK, 0); }
		public TerminalNode UNDERSCORE() { return getToken(rangesParser.UNDERSCORE, 0); }
		public TerminalNode DASH() { return getToken(rangesParser.DASH, 0); }
		public TerminalNode FLOORDIV() { return getToken(rangesParser.FLOORDIV, 0); }
		public TerminalNode LSHIFT() { return getToken(rangesParser.LSHIFT, 0); }
		public TerminalNode RSHIFT() { return getToken(rangesParser.RSHIFT, 0); }
		public SymbolContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_symbol; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).enterSymbol(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof rangesListener ) ((rangesListener)listener).exitSymbol(this);
		}
	}

	public final SymbolContext symbol() throws RecognitionException {
		SymbolContext _localctx = new SymbolContext(_ctx, getState());
		enterRule(_localctx, 16, RULE_symbol);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(56);
			_la = _input.LA(1);
			if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 1729382256909221888L) != 0)) ) {
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

	public static final String _serializedATN =
		"\u0004\u0001<;\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0002\u0002"+
		"\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004\u0002\u0005"+
		"\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007\u0007\u0007\u0002\b\u0007"+
		"\b\u0001\u0000\u0001\u0000\u0001\u0001\u0001\u0001\u0001\u0001\u0003\u0001"+
		"\u0018\b\u0001\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002"+
		"\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0004"+
		"\u0001\u0004\u0001\u0004\u0001\u0004\u0001\u0004\u0001\u0005\u0001\u0005"+
		"\u0001\u0006\u0001\u0006\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007"+
		"\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007"+
		"\u0003\u00077\b\u0007\u0001\b\u0001\b\u0001\b\u0000\u0000\t\u0000\u0002"+
		"\u0004\u0006\b\n\f\u000e\u0010\u0000\u0001\u0002\u0000\u0014:<<9\u0000"+
		"\u0012\u0001\u0000\u0000\u0000\u0002\u0017\u0001\u0000\u0000\u0000\u0004"+
		"\u0019\u0001\u0000\u0000\u0000\u0006\u001e\u0001\u0000\u0000\u0000\b#"+
		"\u0001\u0000\u0000\u0000\n(\u0001\u0000\u0000\u0000\f*\u0001\u0000\u0000"+
		"\u0000\u000e6\u0001\u0000\u0000\u0000\u00108\u0001\u0000\u0000\u0000\u0012"+
		"\u0013\u0003\u0002\u0001\u0000\u0013\u0001\u0001\u0000\u0000\u0000\u0014"+
		"\u0018\u0003\u0004\u0002\u0000\u0015\u0018\u0003\u0006\u0003\u0000\u0016"+
		"\u0018\u0003\b\u0004\u0000\u0017\u0014\u0001\u0000\u0000\u0000\u0017\u0015"+
		"\u0001\u0000\u0000\u0000\u0017\u0016\u0001\u0000\u0000\u0000\u0018\u0003"+
		"\u0001\u0000\u0000\u0000\u0019\u001a\u0005\u0015\u0000\u0000\u001a\u001b"+
		"\u0005\u0012\u0000\u0000\u001b\u001c\u0003\u0000\u0000\u0000\u001c\u001d"+
		"\u0005\u0013\u0000\u0000\u001d\u0005\u0001\u0000\u0000\u0000\u001e\u001f"+
		"\u0005\u0016\u0000\u0000\u001f \u0005\u0012\u0000\u0000 !\u0003\n\u0005"+
		"\u0000!\"\u0005\u0013\u0000\u0000\"\u0007\u0001\u0000\u0000\u0000#$\u0005"+
		"\u0014\u0000\u0000$%\u0005\u0012\u0000\u0000%&\u0003\f\u0006\u0000&\'"+
		"\u0005\u0013\u0000\u0000\'\t\u0001\u0000\u0000\u0000()\u0003\u000e\u0007"+
		"\u0000)\u000b\u0001\u0000\u0000\u0000*+\u0003\u000e\u0007\u0000+\r\u0001"+
		"\u0000\u0000\u0000,7\u0005\u0004\u0000\u0000-7\u0005\u0002\u0000\u0000"+
		".7\u0003\u0010\b\u0000/7\u0005\u000b\u0000\u000007\u0005\f\u0000\u0000"+
		"17\u0005<\u0000\u000023\u0005\u0012\u0000\u000034\u0003\u000e\u0007\u0000"+
		"45\u0005\u0013\u0000\u000057\u0001\u0000\u0000\u00006,\u0001\u0000\u0000"+
		"\u00006-\u0001\u0000\u0000\u00006.\u0001\u0000\u0000\u00006/\u0001\u0000"+
		"\u0000\u000060\u0001\u0000\u0000\u000061\u0001\u0000\u0000\u000062\u0001"+
		"\u0000\u0000\u00007\u000f\u0001\u0000\u0000\u000089\u0007\u0000\u0000"+
		"\u00009\u0011\u0001\u0000\u0000\u0000\u0002\u00176";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}