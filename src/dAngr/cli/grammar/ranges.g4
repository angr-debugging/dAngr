grammar ranges;

import lex;

expression: range;


range
    : bash_range
    | dangr_range
    | python_range
    ;

bash_range: DOLLAR LPAREN bash_content RPAREN;
dangr_range: AMP LPAREN expression RPAREN;
python_range: BANG LPAREN py_content RPAREN;

bash_content: anything;
py_content: anything;
anything: (LETTERS | NUMBERS | symbol | STRING | LPAREN anything RPAREN);

symbol: WS  | BANG | AMP | DOLLAR | COLON | SCOLON | COMMA | QUOTE | SQUOTE | 
        AT | DOT | BAR | BRA | KET | BRACE | KETCE | HAT | HASH | PERC | MUL | ADD | DIV | 
        POW | ASSIGN | EQ | NEQ | LT | GT | LE | GE | AND | OR | QMARK | TILDE | TICK | UNDERSCORE | DASH 
        | FLOORDIV | LSHIFT | RSHIFT;
        