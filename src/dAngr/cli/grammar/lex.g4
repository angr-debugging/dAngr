lexer grammar lex;
HEX_NUMBERS : '0x' [0-9a-fA-F]+;
NUMBERS: NUMBER+;
NUMBER: [0-9];
LETTERS: LETTER+;
LETTER: [a-zA-Z];

SYM_DB : '&sym';
REG_DB : '&reg';
VARS_DB : '&vars';
MEM_DB : '&mem';
STATE : '&state';


STRING : 
    QUOTE (ESCAPED_QUOTE | ('\\x'[0-9]*)| ~["])* QUOTE 
    | SQUOTE (ESCAPED_SINGLE_QUOTE | ('\\x'[0-9]*)| ~['])* SQUOTE;
BINARY_STRING: 'b' STRING ;

ESCAPED_QUOTE : '\\' ESC_SEQ;
ESCAPED_SINGLE_QUOTE : '\\' SESC_SEQ;

// Lexer rules for binary string matching
// Rule for escape sequences
SESC_SEQ: '\\' [\\'0]; 
ESC_SEQ: '\\' [\\"0]; 

ARROW: '->';
LPAREN: '(';
RPAREN: ')';
BANG: '!';
AMP: '&';
DOLLAR: '$';
COLON: ':';
SCOLON: ';';
COMMA: ',';
QUOTE: '"';
SQUOTE: '\'';
AT :'@';
DOT: '.';
BAR: '|';
BRA: '[';
KET: ']';
BRACE: '{';
KETCE: '}';
HAT: '^';
HASH: '#';
PERC: '%';
MUL: '*';
ADD: '+';
DIV: '/';
FLOORDIV: '//';
LSHIFT: '<<';
RSHIFT: '>>';
POW: '**';
ASSIGN: '=';
EQ: '==';
NEQ: '!=';
LT: '<';
GT: '>';
LE: '<=';
GE: '>=';
AND: '&&';
OR: '||';
QMARK: '?';
TILDE: '~';
TICK: '`';
UNDERSCORE: '_';
DASH: '-';


NEWLINE: '\r'? '\n';

WS: [ \t]+;


