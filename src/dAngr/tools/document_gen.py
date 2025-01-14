#generate documentation for the project:

from ..cli.cli_connection import CliConnection
from ..cli.command_line_debugger import CommandLineDebugger
from ..utils import utils

# requires installation of dAngr before running

# generate documentation for dAngr Commands
def document_gen():
    # Create md file with documentation
    with open("./docs/documentation.md", "w") as f:
        f.write("# dAngr Documentation\n\n")
        f.write("This documentation contains all the commands available in the dAngr debugger.\n\n")
        f.write('''
## General dAngr API
### Commands:
    * Commands are case-sensitive.
    * Commands can be called with or without the prefix.
    * Arguments are space separated.
### Variables and objects:
    * there are 4 types in dAngr:
        * &vars: variables that are stored in the debugger.
        * &sym: symbolic objects.
        * &mem: memory objects.
        * &reg: register objects.
    * variables can be created using assignment operator '='.
### Custom commands:
    * Custom commands can be created using the `def` keyword. Arguments specification is passed between brackets and comma separated. Followed by the body.
    * support for `if ...: body [else: body]`. 
    * support for `while ...: bod`y.
    * support for `for ...: body`.

The body is indented on newlines
    Example:
    ```
    def my_command(arg1, arg2):
        print(arg1)
                
''')

        f.write("## Built-in Debugger Commands\n")

        dbg = CommandLineDebugger(CliConnection())
        data, _ = dbg.list_commands_data(True)

        for row in data:
            for d in row:
                d = d.replace('<command>', '**').replace('</command>', '**')
                d = utils.remove_xml_tags(d).replace('\t', '&nbsp;'*4)
                f.write(f"{d}")
            f.write("\n\n")
        
        f.write("\n")
        f.write('''
## Python API
* Execute python commands in the debugger by preceding with `!` (exclamation mark). For example, to print the value of a variable `x`, use `!print(x)`.
 Variables are converted into strings before being passed to the python interpreter.
* Variables can be passed using the long variable name (including the prefix &var, &sym, etc.).
* Python calls may include dAngr or shell commands by using &(...), $(...) respectively.

## Bash API
* Execute shell commands in the debugger by preceding with `%` (percentage sign). For example, to list the files in the current directory, use `%ls`.
* include dAngr or Python commands by using &(...), !(...) respectively.


''')
    print("Documentation generated successfully.")

document_gen()