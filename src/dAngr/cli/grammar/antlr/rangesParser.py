# Generated from /workspaces/dAngr/src/dAngr/cli/grammar/ranges.g4 by ANTLR 4.13.1
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO

def serializedATN():
    return [
        4,1,60,59,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,1,0,1,0,1,1,1,1,1,1,3,1,24,8,1,1,2,1,2,1,2,1,2,
        1,2,1,3,1,3,1,3,1,3,1,3,1,4,1,4,1,4,1,4,1,4,1,5,1,5,1,6,1,6,1,7,
        1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,3,7,55,8,7,1,8,1,8,1,8,0,0,9,
        0,2,4,6,8,10,12,14,16,0,1,2,0,20,58,60,60,57,0,18,1,0,0,0,2,23,1,
        0,0,0,4,25,1,0,0,0,6,30,1,0,0,0,8,35,1,0,0,0,10,40,1,0,0,0,12,42,
        1,0,0,0,14,54,1,0,0,0,16,56,1,0,0,0,18,19,3,2,1,0,19,1,1,0,0,0,20,
        24,3,4,2,0,21,24,3,6,3,0,22,24,3,8,4,0,23,20,1,0,0,0,23,21,1,0,0,
        0,23,22,1,0,0,0,24,3,1,0,0,0,25,26,5,21,0,0,26,27,5,18,0,0,27,28,
        3,0,0,0,28,29,5,19,0,0,29,5,1,0,0,0,30,31,5,22,0,0,31,32,5,18,0,
        0,32,33,3,10,5,0,33,34,5,19,0,0,34,7,1,0,0,0,35,36,5,20,0,0,36,37,
        5,18,0,0,37,38,3,12,6,0,38,39,5,19,0,0,39,9,1,0,0,0,40,41,3,14,7,
        0,41,11,1,0,0,0,42,43,3,14,7,0,43,13,1,0,0,0,44,55,5,4,0,0,45,55,
        5,2,0,0,46,55,3,16,8,0,47,55,5,11,0,0,48,55,5,12,0,0,49,55,5,60,
        0,0,50,51,5,18,0,0,51,52,3,14,7,0,52,53,5,19,0,0,53,55,1,0,0,0,54,
        44,1,0,0,0,54,45,1,0,0,0,54,46,1,0,0,0,54,47,1,0,0,0,54,48,1,0,0,
        0,54,49,1,0,0,0,54,50,1,0,0,0,55,15,1,0,0,0,56,57,7,0,0,0,57,17,
        1,0,0,0,2,23,54
    ]

class rangesParser ( Parser ):

    grammarFileName = "ranges.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "'&sym'", "'&reg'", "'&vars'", 
                     "'&mem'", "'&state'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "'->'", "'('", 
                     "')'", "'!'", "'&'", "'$'", "':'", "';'", "','", "'\"'", 
                     "'''", "'@'", "'.'", "'|'", "'['", "']'", "'{'", "'}'", 
                     "'^'", "'#'", "'%'", "'*'", "'+'", "'/'", "'//'", "'<<'", 
                     "'>>'", "'**'", "'='", "'=='", "'!='", "'<'", "'>'", 
                     "'<='", "'>='", "'&&'", "'||'", "'?'", "'~'", "'`'", 
                     "'_'", "'-'" ]

    symbolicNames = [ "<INVALID>", "HEX_NUMBERS", "NUMBERS", "NUMBER", "LETTERS", 
                      "LETTER", "SYM_DB", "REG_DB", "VARS_DB", "MEM_DB", 
                      "STATE", "STRING", "BINARY_STRING", "ESCAPED_QUOTE", 
                      "ESCAPED_SINGLE_QUOTE", "SESC_SEQ", "ESC_SEQ", "ARROW", 
                      "LPAREN", "RPAREN", "BANG", "AMP", "DOLLAR", "COLON", 
                      "SCOLON", "COMMA", "QUOTE", "SQUOTE", "AT", "DOT", 
                      "BAR", "BRA", "KET", "BRACE", "KETCE", "HAT", "HASH", 
                      "PERC", "MUL", "ADD", "DIV", "FLOORDIV", "LSHIFT", 
                      "RSHIFT", "POW", "ASSIGN", "EQ", "NEQ", "LT", "GT", 
                      "LE", "GE", "AND", "OR", "QMARK", "TILDE", "TICK", 
                      "UNDERSCORE", "DASH", "NEWLINE", "WS" ]

    RULE_expression = 0
    RULE_range = 1
    RULE_dangr_range = 2
    RULE_bash_range = 3
    RULE_python_range = 4
    RULE_bash_content = 5
    RULE_py_content = 6
    RULE_anything = 7
    RULE_symbol = 8

    ruleNames =  [ "expression", "range", "dangr_range", "bash_range", "python_range", 
                   "bash_content", "py_content", "anything", "symbol" ]

    EOF = Token.EOF
    HEX_NUMBERS=1
    NUMBERS=2
    NUMBER=3
    LETTERS=4
    LETTER=5
    SYM_DB=6
    REG_DB=7
    VARS_DB=8
    MEM_DB=9
    STATE=10
    STRING=11
    BINARY_STRING=12
    ESCAPED_QUOTE=13
    ESCAPED_SINGLE_QUOTE=14
    SESC_SEQ=15
    ESC_SEQ=16
    ARROW=17
    LPAREN=18
    RPAREN=19
    BANG=20
    AMP=21
    DOLLAR=22
    COLON=23
    SCOLON=24
    COMMA=25
    QUOTE=26
    SQUOTE=27
    AT=28
    DOT=29
    BAR=30
    BRA=31
    KET=32
    BRACE=33
    KETCE=34
    HAT=35
    HASH=36
    PERC=37
    MUL=38
    ADD=39
    DIV=40
    FLOORDIV=41
    LSHIFT=42
    RSHIFT=43
    POW=44
    ASSIGN=45
    EQ=46
    NEQ=47
    LT=48
    GT=49
    LE=50
    GE=51
    AND=52
    OR=53
    QMARK=54
    TILDE=55
    TICK=56
    UNDERSCORE=57
    DASH=58
    NEWLINE=59
    WS=60

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.1")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class ExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def range_(self):
            return self.getTypedRuleContext(rangesParser.RangeContext,0)


        def getRuleIndex(self):
            return rangesParser.RULE_expression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpression" ):
                listener.enterExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpression" ):
                listener.exitExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpression" ):
                return visitor.visitExpression(self)
            else:
                return visitor.visitChildren(self)




    def expression(self):

        localctx = rangesParser.ExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_expression)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 18
            self.range_()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def dangr_range(self):
            return self.getTypedRuleContext(rangesParser.Dangr_rangeContext,0)


        def bash_range(self):
            return self.getTypedRuleContext(rangesParser.Bash_rangeContext,0)


        def python_range(self):
            return self.getTypedRuleContext(rangesParser.Python_rangeContext,0)


        def getRuleIndex(self):
            return rangesParser.RULE_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRange" ):
                listener.enterRange(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRange" ):
                listener.exitRange(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRange" ):
                return visitor.visitRange(self)
            else:
                return visitor.visitChildren(self)




    def range_(self):

        localctx = rangesParser.RangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_range)
        try:
            self.state = 23
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [21]:
                self.enterOuterAlt(localctx, 1)
                self.state = 20
                self.dangr_range()
                pass
            elif token in [22]:
                self.enterOuterAlt(localctx, 2)
                self.state = 21
                self.bash_range()
                pass
            elif token in [20]:
                self.enterOuterAlt(localctx, 3)
                self.state = 22
                self.python_range()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Dangr_rangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def AMP(self):
            return self.getToken(rangesParser.AMP, 0)

        def LPAREN(self):
            return self.getToken(rangesParser.LPAREN, 0)

        def expression(self):
            return self.getTypedRuleContext(rangesParser.ExpressionContext,0)


        def RPAREN(self):
            return self.getToken(rangesParser.RPAREN, 0)

        def getRuleIndex(self):
            return rangesParser.RULE_dangr_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDangr_range" ):
                listener.enterDangr_range(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDangr_range" ):
                listener.exitDangr_range(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDangr_range" ):
                return visitor.visitDangr_range(self)
            else:
                return visitor.visitChildren(self)




    def dangr_range(self):

        localctx = rangesParser.Dangr_rangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_dangr_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 25
            self.match(rangesParser.AMP)
            self.state = 26
            self.match(rangesParser.LPAREN)
            self.state = 27
            self.expression()
            self.state = 28
            self.match(rangesParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Bash_rangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DOLLAR(self):
            return self.getToken(rangesParser.DOLLAR, 0)

        def LPAREN(self):
            return self.getToken(rangesParser.LPAREN, 0)

        def bash_content(self):
            return self.getTypedRuleContext(rangesParser.Bash_contentContext,0)


        def RPAREN(self):
            return self.getToken(rangesParser.RPAREN, 0)

        def getRuleIndex(self):
            return rangesParser.RULE_bash_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBash_range" ):
                listener.enterBash_range(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBash_range" ):
                listener.exitBash_range(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBash_range" ):
                return visitor.visitBash_range(self)
            else:
                return visitor.visitChildren(self)




    def bash_range(self):

        localctx = rangesParser.Bash_rangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_bash_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 30
            self.match(rangesParser.DOLLAR)
            self.state = 31
            self.match(rangesParser.LPAREN)
            self.state = 32
            self.bash_content()
            self.state = 33
            self.match(rangesParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Python_rangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def BANG(self):
            return self.getToken(rangesParser.BANG, 0)

        def LPAREN(self):
            return self.getToken(rangesParser.LPAREN, 0)

        def py_content(self):
            return self.getTypedRuleContext(rangesParser.Py_contentContext,0)


        def RPAREN(self):
            return self.getToken(rangesParser.RPAREN, 0)

        def getRuleIndex(self):
            return rangesParser.RULE_python_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPython_range" ):
                listener.enterPython_range(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPython_range" ):
                listener.exitPython_range(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitPython_range" ):
                return visitor.visitPython_range(self)
            else:
                return visitor.visitChildren(self)




    def python_range(self):

        localctx = rangesParser.Python_rangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_python_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 35
            self.match(rangesParser.BANG)
            self.state = 36
            self.match(rangesParser.LPAREN)
            self.state = 37
            self.py_content()
            self.state = 38
            self.match(rangesParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Bash_contentContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def anything(self):
            return self.getTypedRuleContext(rangesParser.AnythingContext,0)


        def getRuleIndex(self):
            return rangesParser.RULE_bash_content

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBash_content" ):
                listener.enterBash_content(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBash_content" ):
                listener.exitBash_content(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBash_content" ):
                return visitor.visitBash_content(self)
            else:
                return visitor.visitChildren(self)




    def bash_content(self):

        localctx = rangesParser.Bash_contentContext(self, self._ctx, self.state)
        self.enterRule(localctx, 10, self.RULE_bash_content)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 40
            self.anything()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Py_contentContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def anything(self):
            return self.getTypedRuleContext(rangesParser.AnythingContext,0)


        def getRuleIndex(self):
            return rangesParser.RULE_py_content

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPy_content" ):
                listener.enterPy_content(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPy_content" ):
                listener.exitPy_content(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitPy_content" ):
                return visitor.visitPy_content(self)
            else:
                return visitor.visitChildren(self)




    def py_content(self):

        localctx = rangesParser.Py_contentContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_py_content)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 42
            self.anything()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class AnythingContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LETTERS(self):
            return self.getToken(rangesParser.LETTERS, 0)

        def NUMBERS(self):
            return self.getToken(rangesParser.NUMBERS, 0)

        def symbol(self):
            return self.getTypedRuleContext(rangesParser.SymbolContext,0)


        def STRING(self):
            return self.getToken(rangesParser.STRING, 0)

        def BINARY_STRING(self):
            return self.getToken(rangesParser.BINARY_STRING, 0)

        def WS(self):
            return self.getToken(rangesParser.WS, 0)

        def LPAREN(self):
            return self.getToken(rangesParser.LPAREN, 0)

        def anything(self):
            return self.getTypedRuleContext(rangesParser.AnythingContext,0)


        def RPAREN(self):
            return self.getToken(rangesParser.RPAREN, 0)

        def getRuleIndex(self):
            return rangesParser.RULE_anything

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAnything" ):
                listener.enterAnything(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAnything" ):
                listener.exitAnything(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAnything" ):
                return visitor.visitAnything(self)
            else:
                return visitor.visitChildren(self)




    def anything(self):

        localctx = rangesParser.AnythingContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_anything)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 54
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,1,self._ctx)
            if la_ == 1:
                self.state = 44
                self.match(rangesParser.LETTERS)
                pass

            elif la_ == 2:
                self.state = 45
                self.match(rangesParser.NUMBERS)
                pass

            elif la_ == 3:
                self.state = 46
                self.symbol()
                pass

            elif la_ == 4:
                self.state = 47
                self.match(rangesParser.STRING)
                pass

            elif la_ == 5:
                self.state = 48
                self.match(rangesParser.BINARY_STRING)
                pass

            elif la_ == 6:
                self.state = 49
                self.match(rangesParser.WS)
                pass

            elif la_ == 7:
                self.state = 50
                self.match(rangesParser.LPAREN)
                self.state = 51
                self.anything()
                self.state = 52
                self.match(rangesParser.RPAREN)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SymbolContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WS(self):
            return self.getToken(rangesParser.WS, 0)

        def BANG(self):
            return self.getToken(rangesParser.BANG, 0)

        def AMP(self):
            return self.getToken(rangesParser.AMP, 0)

        def DOLLAR(self):
            return self.getToken(rangesParser.DOLLAR, 0)

        def COLON(self):
            return self.getToken(rangesParser.COLON, 0)

        def SCOLON(self):
            return self.getToken(rangesParser.SCOLON, 0)

        def COMMA(self):
            return self.getToken(rangesParser.COMMA, 0)

        def QUOTE(self):
            return self.getToken(rangesParser.QUOTE, 0)

        def SQUOTE(self):
            return self.getToken(rangesParser.SQUOTE, 0)

        def AT(self):
            return self.getToken(rangesParser.AT, 0)

        def DOT(self):
            return self.getToken(rangesParser.DOT, 0)

        def BAR(self):
            return self.getToken(rangesParser.BAR, 0)

        def BRA(self):
            return self.getToken(rangesParser.BRA, 0)

        def KET(self):
            return self.getToken(rangesParser.KET, 0)

        def BRACE(self):
            return self.getToken(rangesParser.BRACE, 0)

        def KETCE(self):
            return self.getToken(rangesParser.KETCE, 0)

        def HAT(self):
            return self.getToken(rangesParser.HAT, 0)

        def HASH(self):
            return self.getToken(rangesParser.HASH, 0)

        def PERC(self):
            return self.getToken(rangesParser.PERC, 0)

        def MUL(self):
            return self.getToken(rangesParser.MUL, 0)

        def ADD(self):
            return self.getToken(rangesParser.ADD, 0)

        def DIV(self):
            return self.getToken(rangesParser.DIV, 0)

        def POW(self):
            return self.getToken(rangesParser.POW, 0)

        def ASSIGN(self):
            return self.getToken(rangesParser.ASSIGN, 0)

        def EQ(self):
            return self.getToken(rangesParser.EQ, 0)

        def NEQ(self):
            return self.getToken(rangesParser.NEQ, 0)

        def LT(self):
            return self.getToken(rangesParser.LT, 0)

        def GT(self):
            return self.getToken(rangesParser.GT, 0)

        def LE(self):
            return self.getToken(rangesParser.LE, 0)

        def GE(self):
            return self.getToken(rangesParser.GE, 0)

        def AND(self):
            return self.getToken(rangesParser.AND, 0)

        def OR(self):
            return self.getToken(rangesParser.OR, 0)

        def QMARK(self):
            return self.getToken(rangesParser.QMARK, 0)

        def TILDE(self):
            return self.getToken(rangesParser.TILDE, 0)

        def TICK(self):
            return self.getToken(rangesParser.TICK, 0)

        def UNDERSCORE(self):
            return self.getToken(rangesParser.UNDERSCORE, 0)

        def DASH(self):
            return self.getToken(rangesParser.DASH, 0)

        def FLOORDIV(self):
            return self.getToken(rangesParser.FLOORDIV, 0)

        def LSHIFT(self):
            return self.getToken(rangesParser.LSHIFT, 0)

        def RSHIFT(self):
            return self.getToken(rangesParser.RSHIFT, 0)

        def getRuleIndex(self):
            return rangesParser.RULE_symbol

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSymbol" ):
                listener.enterSymbol(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSymbol" ):
                listener.exitSymbol(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSymbol" ):
                return visitor.visitSymbol(self)
            else:
                return visitor.visitChildren(self)




    def symbol(self):

        localctx = rangesParser.SymbolContext(self, self._ctx, self.state)
        self.enterRule(localctx, 16, self.RULE_symbol)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 56
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 1729382256909221888) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx





