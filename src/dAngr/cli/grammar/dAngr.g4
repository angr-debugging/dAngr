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
            (NEWLINE|statement| function_def)* )WS* EOF;

statement:  control_flow |
            // dangr_command NEWLINE| 
            assignment NEWLINE | 
            expression NEWLINE | 
            static_var NEWLINE |
            ext_command NEWLINE ;

expression :
    (identifier DOT)? (DIV)? identifier (WS (identifier ASSIGN)?expression_part)*
    | expression_part
    ;

expression_part :
    CIF WS? condition WS? CTHEN WS? expression_part WS? CELSE WS? expression_part # ExpressionIf
    | LPAREN WS? expression WS? RPAREN # ExpressionParenthesis
    | RANGE LPAREN WS? expression_part WS? (COMMA WS?expression_part WS?(COMMA WS?expression_part WS?)?)?  RPAREN # ExpressionRange
    | expression_part WS IN WS expression_part # ExpressionIn
    | range # ExpressionAlt // python, bash, dangr
    | reference # ExpressionReference
    | BOOL # ExpressionBool
    | object (WS? operation WS? expression_part) # ExpressionOperation
    | object # ExpressionObject
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

body : INDENT (fstatement NEWLINE?)+ DEDENT ;

fstatement: BREAK|CONTINUE|(RETURN WS expression)|statement ;

iterable : expression ;

parameters : identifier (WS? COMMA WS? identifier)* ;

condition : expression ;
operation : ADD | 
        DASH | 
        MUL | 
        DIV | 
        PERC | 
        POW | 
        EQ | 
        NEQ | 
        GT | 
        LT | 
        LE | 
        GE | 
        AND | 
        OR 
        FLOORDIV |
        LSHIFT |
        RSHIFT |
        AMP |
        BAR 
        ;



py_basic_content: identifier WS? LPAREN WS? (py_content)* RPAREN  ;
py_content: (reference |range | anything | LPAREN py_content RPAREN)+ ;
bash_content: (reference | range | anything | LPAREN bash_content RPAREN)*;



reference: 
        (VARS_DB|REG_DB|SYM_DB) DOT identifier BANG?| // ReferenceObject
        STATE |
        MEM_DB BRA WS? index (WS? ARROW WS? index)? KET BANG?// MemoryObject with size and length
        ;



index : DASH? expression;
identifier : (LETTERS|UNDERSCORE|special_words UNDERSCORE)(LETTERS|NUMBERS|UNDERSCORE|special_words)*;
numeric : NUMBERS | HEX_NUMBERS;

object : identifier BANG?  # IDObject
    | (DASH)? numeric # NumericObject
    | BOOL # BoolObject
    | reference # ReferenceObject
    | object DOT identifier # PropertyObject
    | object BRA WS? index WS? KET # IndexedPropertyObject
    | object BRA WS? index WS? COLON WS? index? WS? KET # SliceStartEndObject // slice from start to end
    | object BRA WS? index WS? ARROW WS? index WS? KET #SlideStartLengthObject // slice from start to start + number
    | BRA WS? object? (WS? COMMA WS? object)* WS? KET #ListObject // list
    | BRACE WS? (STRING WS? COLON WS? object (WS? COMMA WS? STRING WS? COLON WS? object))* WS? KETCE # DictionaryObject // dict
    | STRING #StringObject
    | BINARY_STRING #BinaryStringObject
    ; 

anything: (LETTERS | NUMBERS | symbol | STRING | BINARY_STRING | WS | LPAREN anything RPAREN | special_words);

special_words : STATIC | DEF | IF | ELSE | FOR | IN | WHILE | BOOL | HELP | CIF | CTHEN | CELSE | RETURN | BREAK | CONTINUE | RANGE;

STATIC : 'static';

CIF : 'IIF';
CTHEN: 'THEN';
CELSE: 'ELSE';

RANGE : 'range';
DEF : 'def';
IF : 'if';
ELSE : 'else';
FOR : 'for';
IN : 'in';
WHILE : 'while';
BOOL: 'True' | 'False';
HELP : 'help';
RETURN : 'return';
BREAK : 'break';
CONTINUE : 'continue';
NEWLINE: ('\r'? '\n' ' '*) ;

WS: ' '+ ;