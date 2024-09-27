grammar ranges;

import lex;

statement: range;


range
    : bash_range
    | dangr_range
    | python_range
    ;

bash_range: DOLLAR '(' bash_content ')';
dangr_range: AMP '(' statement ')';
python_range: BANG '(' py_content ')';

bash_content: anything;
py_content: anything;
anything: LETTERS | NUMBERS | symbol | STRING;

symbol: WS | LPAREN | RPAREN | BANG | AMP | DOLLAR | COLON | SCOLON | COMMA | QUOTE | SQUOTE | 
        AT | DOT | BAR | BRA | KET | BRACE | KETCE | HAT | HASH | PERC | TIMES | ADD | DIV | 
        POW | ASSIGN | EQ | NEQ | LT | GT | LE | GE | AND | OR | QMARK | TILDE | TICK | UNDERSCORE | DASH;
