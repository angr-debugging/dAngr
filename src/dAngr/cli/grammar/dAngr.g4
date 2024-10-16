grammar dAngr;
tokens { INDENT, DEDENT }
import ranges;

@lexer::header{
from antlr_denter.DenterHelper import DenterHelper
from .dAngrParser import dAngrParser
}
@lexer::members {
class dAngrDenter(DenterHelper):
    def __init__(self, lexer, nl_token, indent_token, dedent_token, ignore_eof):
        super().__init__(nl_token, indent_token, dedent_token, ignore_eof)
        self.lexer: dangr_Lexer = lexer

    def pull_token(self):
        return super(dAngrLexer, self.lexer).nextToken()

denter = None

def nextToken(self):
    if not self.denter:
        self.denter = self.dAngrDenter(self, self.NEWLINE, dAngrParser.INDENT, dAngrParser.DEDENT, False)
    return self.denter.next_token()

}

@parser::header {
import re as rex
}

script : ((QMARK|HELP) (WS identifier)? NEWLINE|
            (NEWLINE|statement| function_def)* ) EOF;

statement:  control_flow |
            // dangr_command NEWLINE| 
            assignment NEWLINE | 
            expression NEWLINE | 
            static_var NEWLINE |
            ext_command NEWLINE ;

expression
    :     identifier (WS (identifier ASSIGN)?expression_part)* // dangr command
    |     constraint
    |     expression_part;

constraint :
           CIF WS? condition WS? CTHEN WS? expression_part WS? CELSE WS? expression_part;


expression_part: LPAREN WS? expression WS? RPAREN
    | range // python, bash, dangr
    | reference
    | object (WS? operation WS? expression)? 
    ;



assignment : (static_var| object) WS? ASSIGN WS? expression ;
static_var : STATIC WS identifier ;
// dangr_command : identifier (WS (identifier ASSIGN)?expression_part)* | add_constraint;
// add_constraint : 'add_constraints' WS object WS? operation WS? expression ;

ext_command
    : BANG py_basic_content // python
    | AMP expression // dAngr
    | DOLLAR bash_content // bash
    ;

control_flow
    : IF WS condition WS?COLON body else_?
    | FOR WS identifier (WS? COMMA WS? identifier)? WS IN WS iterable WS?COLON body
    | WHILE WS condition WS?COLON body
    ;
else_: ELSE WS?COLON body ;

function_def
    : DEF WS identifier WS?LPAREN parameters? RPAREN WS? COLON body
    ;

body : INDENT (statement NEWLINE?)+ DEDENT ;

iterable : object | 'range' LPAREN WS? numeric WS? (COMMA WS?numeric WS?)?  RPAREN ;

parameters : identifier (WS? COMMA WS? identifier)* ;

condition : expression ;
operation : ADD | DASH | TIMES | DIV | PERC | POW | EQ | NEQ | GT | LT | LE | GE | AND | OR ;



py_basic_content: identifier WS? LPAREN WS? (py_content)* RPAREN  ;
py_content: (reference |range | anything | LPAREN py_content RPAREN)+ ;

reference: 
        (VARS_DB|REG_DB|SYM_DB) DOT identifier | // ReferenceObject
        STATE |
        MEM_DB BRA WS? numeric (WS? ARROW WS? NUMBERS)? KET // MemoryObject with size and length
        ;

bash_content: identifier (range|anything |reference)*;


index : identifier | numeric;
identifier : (LETTERS|UNDERSCORE|special_words UNDERSCORE)(LETTERS|NUMBERS|UNDERSCORE|special_words)*;
numeric : NUMBERS | HEX_NUMBERS;

object : identifier | 
    (ADD|SUB)? NUMBERS |
    HEX_NUMBERS | 
    BOOL |
    reference |
    object DOT identifier | // property
    object BRA WS? index WS? KET | // indexed property
    object BRA WS? numeric WS? COLON WS? numeric WS? KET | // slice from start to end
    object BRA WS? numeric WS? ARROW WS? NUMBERS WS? KET | // slice from start to start + number
    BRA WS? object (WS? COMMA WS? object)* WS? KET | // list
    BRACE WS? (STRING WS? COLON WS? object (WS? COMMA WS? STRING WS? COLON WS? object))* WS? KETCE | // dict
    STRING | 
    BINARY_STRING
    ; 

special_words : STATIC | DEF | IF | ELSE | FOR | IN | WHILE | BOOL | HELP | CIF | CTHEN | CELSE;

STATIC : 'static';

CIF : 'IIF';
CTHEN: 'THEN';
CELSE: 'ELSE';

DEF : 'def';
IF : 'if';
ELSE : 'else';
FOR : 'for';
IN : 'in';
WHILE : 'while';
BOOL: 'True' | 'False';
HELP : 'help';
NEWLINE: ('\r'? '\n' ' '*) ;

WS: ' '+ ;