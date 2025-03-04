import pytest

from unittest.mock import Mock

from dAngr.cli.grammar.control_flow import ForLoop, IfThenElse
from dAngr.cli.grammar.parser import lex_input, parse_input
from dAngr.angr_ext.expressions import BashCommand, Comparison, Dictionary, Expression, Listing, Literal, DangrCommand, Operator, Property, PythonCommand, Range, VariableRef
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

    
    def test_lex_false(self):
        for a in self.lex_neg_tests:
            #must raise exception
            with pytest.raises(ParseError) as exc_info:
                r = lex_input(a)
            assert exc_info is not None, f"Expected exception when lexing {a}, got {r}"

    
    def test_lex_true(self):
        for a in self.lex_tests:
            #must work
            r = lex_input(a)
            assert r is not None

    
    def test_lex_compound(self):
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
        'run': [DangrCommand('run',None)],
        'run 0 1 2': [DangrCommand('run', None, Literal(0), Literal(1), Literal(2))],
        "!print(&vars.x)" : [PythonCommand(Literal("print("), VariableRef(Literal('x')), Literal(")"))],
        "!print('x')" : [PythonCommand(Literal("print('x')"))],
        '$ls' : [BashCommand(Literal('ls'))],
        '&run' : [DangrCommand('run', None)],
        'run "4" "3" "4"': [DangrCommand('run', None, Literal('4'), Literal('3'), Literal('4'))],
        'run "5" !(print(1)) "4"': [DangrCommand('run', None, Literal('5'), PythonCommand(Literal("print(1)")), Literal('4'))],
        'run "6" $(ls -la) "4"': [DangrCommand('run', None, Literal('6'), BashCommand(Literal("ls -la")), Literal('4'))],
        'run "7" !(print($(ls -la))) "4"': [DangrCommand('run', None, Literal('7'), PythonCommand(Literal("print("),BashCommand(Literal("ls -la")), Literal(")")), Literal('4'))],
"""
for i in range(10):
    !print(&vars.i)
""": [ForLoop(Range(Literal(10)), Body([PythonCommand('print(',VariableRef(Literal('i')),')')]),VariableRef(Literal('i')))],
"""
for i,n in {"1":2, "3":4}:
    !print(&vars.i,&vars.n)
""": [ForLoop(Dictionary({"1": Literal(2), "3": Literal(4)}), Body([PythonCommand('print(',VariableRef(Literal('i')),',',VariableRef(Literal('n')),')')]),VariableRef(Literal('n')), VariableRef(Literal('i')))],
    '{"1":2, "3":4}': [Dictionary({"1": Literal(2), "3": Literal(4)})],
"""
for i,n in [5,6,7,8,9]:
    !print(&vars.i,&vars.n)
""": [ForLoop(Listing([Literal(5), Literal(6), Literal(7), Literal(8), Literal(9)]), Body([PythonCommand('print(',VariableRef(Literal('i')),',',VariableRef(Literal("n")),')')]),VariableRef(Literal('n')), VariableRef(Literal('i')))],
"""
if a != "Hello from Bash":
    !print("Printing from Python: ", &vars.a)
    x = 0
""":[IfThenElse(Comparison(VariableRef(Literal('a')), Operator.NEQ, Literal('Hello from Bash')), Body([PythonCommand('print("Printing from Python: ", ', VariableRef(Literal("a")),')'), Assignment(VariableRef(Literal("x")),Literal(0))]))],
"""[1,2,3,4,5]""":[Listing([Literal(1), Literal(2), Literal(3), Literal(4), Literal(5)])],
'!print("Printing from Python: ", &vars.a)': [PythonCommand('print("Printing from Python: ", ', VariableRef(Literal("a")),')')],
"static i = 0": [Assignment(VariableRef(Literal('i'),True), Literal(0))],
'!("{:08x} {:08x} {:08x}".format(int(&vars.password0,16), int(&vars.password1,16), int(&vars.password2,16)))':[PythonCommand('"{:08x} {:08x} {:08x}"','.format(int(', VariableRef(Literal('password0')),',16), int(', VariableRef(Literal('password1')),',16), int(', VariableRef(Literal('password2')),',16))')],
'a2 = (get_symbol &vars.password2 "int")': [Assignment(VariableRef(Literal('a2')), DangrCommand('get_symbol', None, VariableRef(Literal('password2')), Literal('int')))],
'a2 = &(get_symbol password2 "int")': [Assignment(VariableRef(Literal('a2')), DangrCommand('get_symbol', None, VariableRef(Literal('password2')), Literal('int')))],
'set_entry_state add_options=[options.LAZY_SOLVES]': [DangrCommand('set_entry_state', None, add_options= Listing([Property(VariableRef(Literal('options')), 'LAZY_SOLVES')]))],
    }

    def test_parse_false(self):
        for a in self.parse_neg_tests:
            #must raise exception
            with pytest.raises(ParseError) as exc_info:
                r = parse_input(a, None)
            assert exc_info is not None, f"Expected exception when parsing {a}, got {r}"
            

    def test_parse_true(self):
        for a in reversed(self.parse_tests):
            r = parse_input(a, None)
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
        r = parse_input(input, None)
        assert r is not None


                