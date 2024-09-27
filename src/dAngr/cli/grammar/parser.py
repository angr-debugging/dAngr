

from typing import Any, List
from antlr4 import CommonTokenStream, InputStream, Lexer, Token
from dAngr.cli.grammar.antlr.dAngrLexer import dAngrLexer
from dAngr.cli.grammar.antlr.dAngrParser import dAngrParser
from dAngr.cli.grammar.error_listener import ErrorListener
from dAngr.cli.grammar.visitor import dAngrVisitor_
from dAngr.cli.grammar.script import Script
from dAngr.exceptions import ParseError
from dAngr.utils.utils import DEBUG


def printTokens(stream:CommonTokenStream, Parser:type[Any], lexer:Any):
    stream.fill()
    result:List[str] = []
    line = -1
    # print token types and value per line, hence if line number changes, print on new line

    switcher = {
                -1: "EOF",
    }
    if getattr(Parser, "INDENT", None):
        switcher[Parser.INDENT] = "INDENT"
        switcher[Parser.DEDENT] = "DEDENT"

    for token in stream.tokens:
        if token.line != line:
            line = token.line
            result.append(f"{token.line}: ")
        if token.type in switcher:
            token_type = switcher[token.type]
        else:
            token_type = lexer.ruleNames[token.type-1]
        result[-1] +=f"{token_type}({token.text}) "


    # for token in stream.tokens:
    #     switcher = {
    #         -1: "EOF",
    #     }
    #     if getattr(Parser, "INDENT", None):
    #         switcher[Parser.INDENT] = "INDENT"
    #         switcher[Parser.DEDENT] = "DEDENT"
    #     if token.type in switcher:
    #         token_type = switcher[token.type]
    #     else:
    #         token_type = lexer.ruleNames[token.type-1]
    #     result.append(f"Token: {token.text}, Type: {token_type}")
    if DEBUG:
        print("\n".join(result))
    return result

def lex_input(input, Lexer:type[Any]=dAngrLexer, Parser:type[Any]=dAngrParser):
    input_stream = InputStream(input)
    lexer = Lexer(input_stream)
    stream = CommonTokenStream(lexer)
    error_listener = ErrorListener()
    lexer.addErrorListener(error_listener)
    if error_listener._errors:
        raise ParseError("\n".join([e for e in error_listener.errors]))
    return printTokens(stream, Parser, lexer)

def parse_input(input:str, Lexer:type[Any]=dAngrLexer, Parser:type[Any] = dAngrParser, Visitor:type[Any]|None = dAngrVisitor_)-> Script:
    input_stream = InputStream(input)
    lexer = Lexer(input_stream)
    stream = CommonTokenStream(lexer)
    if DEBUG:
        printTokens(stream, Parser, lexer)
    parser = Parser(stream)
    error_listener = ErrorListener()
    parser.removeErrorListeners()  # Remove default console error listener
    parser.addErrorListener(error_listener)
    tree = parser.script()
    if not tree:
        raise ParseError("No tree generated")
    if DEBUG:
        print(tree.toStringTree(recog=parser))
    if error_listener._errors:
        raise ParseError("\n".join([e for e in error_listener.errors]))

    
    if Visitor:
        visitor = Visitor()
        return visitor.visit(tree)
    raise ParseError("No visitor provided")
