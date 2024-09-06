
import re
from typing import Callable

import claripy.ops

# Tokenizing the input, supporting symbols, numbers, and operators
token_pattern = re.compile(
    r"\s*(//|==|!=|>=|<=|<<|>>|\*\*|\.\.|&&|\|\||[()<>!=+\-*/%^&|~]|b'[^']*'|[A-Za-z_]\w*|0x[0-9a-fA-F]+|\d+|\$[a-z]+\.\w+(?:\^\d+)?)"
)

def tokenize(expression):
    tokens = []
    for match in token_pattern.findall(expression):
        if match.startswith('$'):
            tokens.append(('SYMBOL', match))
        elif match.startswith('0x'):
            # Hexadecimal number
            tokens.append(('NUMBER', int(match, 16)))
        elif match.startswith("b'"):
            # Binary string
            # binary_string = match[2:-1]  # Strip 'b' and the surrounding quotes
            tokens.append(('SYMBOL', match))
        elif match.isdigit():
            tokens.append(('NUMBER', int(match)))
        elif match.isidentifier():  # Recognizes symbols (variable names)
            tokens.append(('SYMBOL', match))
        elif match in {'(', ')'}:
            tokens.append(("BRACKET", match))
        else:
            tokens.append(('OP', match))
    return tokens

# Precedence and associativity (left for left-associative, right for right-associative)
precedence = {
    '||': 1, '&&': 2,
    '|': 3, '^': 4, '&': 5,
    '==': 6, '!=': 6, '>=': 6, '<=': 6, '>': 6, '<': 6,
    '<<': 7, '>>': 7,
    '+': 8, '-': 8,
    '*': 9, '/': 9, '%': 9, '//': 9,
    '**': 10,
    '~': 11, '-u': 11, '+u': 11, 'not': 11, 'abs': 11
}

right_associative = {'**', '-u', '+u', 'not', 'abs'}

# Mapping operations to their precedence group
# op_map = {
#     '&&': 'and', '||': 'or',
#     '==': 'equal', '!=': 'not-equal',
#     '>=': 'greater-equal', '<=': 'less-equal',
#     '>': 'greater', '<': 'less',
#     '<<': 'left-shift', '>>': 'right-shift',
#     '+': 'addition', '-': 'subtraction',
#     '*': 'multiplication', '/': 'division', '%': 'modulo', '//': 'floor-division',
#     '**': 'power',
#     '&': 'bitwise-and', '|': 'bitwise-or', '^': 'xor',
#     '~': 'invert', '-u': 'negation', '+u': 'positive', 'not': 'not', 'abs': 'absolute'
# }

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def parse(self):
        return self.parse_expression()

    def parse_expression(self, precedence_level=1):
        left = self.parse_primary()

        while self.pos < len(self.tokens):
            lookahead = self.lookahead()
            if lookahead and lookahead[0] == 'OP' and precedence.get(lookahead[1], -1) >= precedence_level:
                token = self.consume('OP')
                next_precedence = precedence[token[1]] + (1 if token[1] not in right_associative else 0)
                right = self.parse_expression(next_precedence)
                left = (token[1], left, right)
            else:
                break

        return left

    def parse_primary(self):
        if self.match('NUMBER'):
            return self.consume('NUMBER')
        elif self.match('SYMBOL'):
            return self.consume('SYMBOL')
        elif self.match('OP') and self.lookahead()[1] in {'-', '+', '~'}: # type: ignore
            token = self.consume('OP')
            expr = self.parse_expression(precedence[token[1]] + 1)
            return (token[1], expr)  # unary operations
        elif self.match('BRACKET'):
            self.consume('BRACKET')
            expr = self.parse_expression()
            self.consume('BRACKET')
            return expr
        else:
            raise SyntaxError(f"Unexpected token: {self.lookahead()}")

    def match(self, *token_types):
        if self.pos < len(self.tokens) and self.tokens[self.pos][0] in token_types:
            return True
        return False

    def consume(self, *token_types):
        if self.match(*token_types):
            current_token = self.tokens[self.pos]
            self.pos += 1
            return current_token
        else:
            raise SyntaxError(f"Expected one of {token_types}, got {self.tokens[self.pos]}")

    def lookahead(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None



import claripy

def op_to_claripy(op_type, tp:claripy.ast.BV|claripy.ast.Bool|claripy.ast.FP|claripy.ast.String) :
    if op_type == '&&':
        return tp.__and__
    elif op_type == '||':
        return tp.__or__
    elif op_type == '==':
        return tp.__eq__
    elif op_type == '!=':
        return tp.__ne__
    elif op_type == '>=':
        return tp.__ge__
    elif op_type == '<=':
        return tp.__le__
    elif op_type == '>':
        return tp.__gt__
    elif op_type == '<':
        return tp.__lt__
    elif op_type == '<<':
        return tp.__lshift__
    elif op_type == '>>':
        return tp.__rshift__
    elif op_type == '+':
        return tp.__add__
    elif op_type == '-':
        return tp.__sub__
    elif op_type == '*':
        return tp.__mul__
    elif op_type == '/':
        return tp.__floordiv__
    elif op_type == '%':
        return tp.__mod__
    elif op_type == '//':
        return tp.__rmod__
    elif op_type == '**':
        return tp.__pow__
    raise ValueError(f"Unknown operator: {op_type}")
    
Symbol_Handler=Callable[[str|int|bytes,bool], claripy.ast.BV|bytes|int|claripy.ast.FP|claripy.ast.String]

def ast_to_claripy(node, symbol_Handler:Symbol_Handler):
    """Recursively convert an AST into a Claripy expression."""
    if isinstance(node, tuple):
        if not isinstance(node[1], tuple):
            if node[0] == 'NUMBER':
                return claripy.BVV(node[1], 32)
            elif node[0] == 'SYMBOL':
                if node[1].startswith("b'") and node[1].endswith("'"):
                    return bytes(node[1][2:-1], 'utf-8')
                return symbol_Handler(node[1],False)
            else:
                raise ValueError(f"Unknown node type: {node[0]}")
        else:
            l = ast_to_claripy(node[1], symbol_Handler)
            r = ast_to_claripy(node[2], symbol_Handler)
            op_type = op_to_claripy(node[0],l)
            return op_type(r)
    else:
        raise ValueError(f"Unknown node type: {node[0]}")

def convert(expression:str, symbol_Handler:Symbol_Handler):
    tokens = tokenize(expression)
    parser = Parser(tokens)
    parsed_expression = parser.parse()

    return ast_to_claripy(parsed_expression, symbol_Handler)