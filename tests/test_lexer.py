import pytest

from unittest.mock import AsyncMock

from dAngr.cli.grammar.control_flow import ForLoop, IfThenElse
from dAngr.cli.grammar.parser import lex_input, parse_input
from dAngr.cli.grammar.expressions import BashCommand, Comparison, Dictionary, Expression, Iterable, Listing, Literal, DangrCommand, Operator, PythonCommand, Range, VariableRef
from dAngr.cli.grammar.script import Body, Script
from dAngr.cli.grammar.statements import Assignment
from dAngr.exceptions import ParseError


class TestLexer:

    def setup_method(self):
        pass
    def teardown_method(self):
        pass

    lex_neg_tests = [
    ]
    lex_tests = [
        "",
        "%a"
        'cmd_0_1_',
        '_cmd_0_2',
        'cmd3 0 1 2',
        "!print('x')",
        '$ls',
        '&cmd_0_1_',
        """
if a != "Hello from Bash":
    !print("Printing from Python: ", a)
    x = 0
    while x < max:
        !print("while: ",x)
        x = x + 1
    !print("Printing from Python: ", a)
    $echo "Hello from Bash" 
""",
"""
for i in range(10):
    !print(i)
""",
"""
for i,n in {"1":2, "3":4}:
    !print(i,n)
""",
"""
for i,n in [5,6,7,8,9]:
    !print(i,n)
""",
"""
if a != "Hello from Bash":
    !print("Printing from Python: ", a)
    x = 0
""",
"""[1,2,3,4,5]asd""",
'!("{:08x} {:08x} {:08x}".format(int(&sym.password0,16), int(&sym.password1,16), int(&sym.password2,16)))'
    ]

    lex_compound_tests = [
        
    ]

    @pytest.mark.asyncio
    async def test_lex_false(self):
        for a in self.lex_neg_tests:
            #must raise exception
            with pytest.raises(ParseError) as exc_info:
                r = lex_input(a)
            assert exc_info is not None, f"Expected exception when lexing {a}, got {r}"

    @pytest.mark.asyncio
    async def test_lex_true(self):
        for a in self.lex_tests:
            #must work
            r = lex_input(a)
            assert r is not None

    @pytest.mark.asyncio
    async def test_lex_compound(self):
        for a in self.lex_compound_tests:
            #must work
            r = lex_input(a)
            print(r)
            assert r is not None

    parse_neg_tests = [
        "%a"
    ]

    parse_tests = {
        "" : [],
        'cmd_0_1_': [DangrCommand('cmd_0_1_')],
        '_cmd_0_2': [DangrCommand('_cmd_0_2' )],
        'cmd3 0 1 2': [DangrCommand('cmd3', Literal(0), Literal(1), Literal(2))],
        "!print(&vars.x)" : [PythonCommand(Literal("print("), VariableRef('x'), Literal(")"))],
        "!print('x')" : [PythonCommand(Literal("print('x')"))],
        '$ls' : [BashCommand(Literal('ls'))],
        '&cmd_0_3_' : [DangrCommand('cmd_0_3_')],
        'cmd "4" "3" "4"': [DangrCommand('cmd', Literal('4'), Literal('3'), Literal('4'))],
        'cmd "5" !(print(1)) "4"': [DangrCommand('cmd', Literal('5'), PythonCommand(Literal("print(1)")), Literal('4'))],
        'cmd "6" $(ls -la) "4"': [DangrCommand('cmd', Literal('6'), BashCommand(Literal("ls -la")), Literal('4'))],
        'cmd "7" !(print($(ls -la))) "4"': [DangrCommand('cmd', Literal('7'), PythonCommand(Literal("print("),BashCommand(Literal("ls -la")), Literal(")")), Literal('4'))],
"""
for i in range(10):
    !print(&vars.i)
""": [ForLoop(Range(10), Body([PythonCommand('print(',VariableRef('i'),')')]),VariableRef('i'))],
"""
for i,n in {"1":2, "3":4}:
    !print(&vars.i,&vars.n)
""": [ForLoop(Dictionary({"1": Literal(2), "3": Literal(4)}), Body([PythonCommand('print(',VariableRef('i'),',',VariableRef("n"),')')]),VariableRef('n'), VariableRef('i'))],
    '{"1":2, "3":4}': [Dictionary({"1": Literal(2), "3": Literal(4)})],
"""
for i,n in [5,6,7,8,9]:
    !print(&vars.i,&vars.n)
""": [ForLoop(Listing([Literal(5), Literal(6), Literal(7), Literal(8), Literal(9)]), Body([PythonCommand('print(',VariableRef('i'),',',VariableRef("n"),')')]),VariableRef('n'), VariableRef('i'))],
"""
if a != "Hello from Bash":
    !print("Printing from Python: ", &vars.a)
    x = 0
""":[IfThenElse(Comparison(VariableRef('a'), Operator.NEQ, Literal('Hello from Bash')), Body([PythonCommand('print("Printing from Python: ", ', VariableRef("a"),')'), Assignment(VariableRef("x"),Literal(0))]))],
"""[1,2,3,4,5]""":[Listing([Literal(1), Literal(2), Literal(3), Literal(4), Literal(5)])],
'!print("Printing from Python: ", &vars.a)': [PythonCommand('print("Printing from Python: ", ', VariableRef("a"),')')],
"static i = 0": [Assignment(VariableRef('i',True), Literal(0))],
'!("{:08x} {:08x} {:08x}".format(int(&vars.password0,16), int(&vars.password1,16), int(&vars.password2,16)))':[PythonCommand('"{:08x} {:08x} {:08x}"','.format(int(', VariableRef('password0'),',16), int(', VariableRef('password1'),',16), int(', VariableRef('password2'),',16))')],
'a2 = (get_symbolic_value &vars.password2 "int")': [Assignment(VariableRef('a2'), DangrCommand('get_symbolic_value', VariableRef('password2'), Literal('int')))],
'a2 = &(get_symbolic_value password2 "int")': [Assignment(VariableRef('a2'), DangrCommand('get_symbolic_value', VariableRef('password2'), Literal('int')))]
    }

    def test_parse_false(self):
        for a in self.parse_neg_tests:
            #must raise exception
            with pytest.raises(ParseError) as exc_info:
                r = parse_input(a)
            assert exc_info is not None, f"Expected exception when parsing {a}, got {r}"
            

    def test_parse_true(self):
        for a in reversed(self.parse_tests):
            r = parse_input(a)
            assert Script(self.parse_tests[a],[]) == r, f"Expected {Script(self.parse_tests[a],[])}, got {r}"

    def test_parse_def(self):
        input = """
def my_function(max, min):
    !print(max)
    !print("Hello from Python")
    r = 5
    a = $(echo "Hello from Bash")
    if a != "Hello from Bash":
        !print("Printing from Python: ", a)
        !print("ok")
    else:
        !print("Printing from Python-else: ", a)
    x = 0
    while x < max:
        !print("while: ",x)
        x = x + 1
    !print("Printing from Python: ", a)
    $echo "Hello from Bash"
    
max = 5
x = 0
my_function max x
!print(x)
!print(6*5)
"""
        r = parse_input(input)
        assert r is not None


                