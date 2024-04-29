#generate documentation for the project:

from dAngr.cli.command_line_debugger import DEBUGGER_COMMANDS
from dAngr.cli.debugger_commands.base import get_cmd_name, get_short_cmd_name

# requires installation of dAngr before running

# generate documentation for dAngr Commands
def document_gen():
    # Create md file with documentation
    with open("./docs/documentation.md", "w") as f:
        f.write("# dAngr Documentation\n\n")
        f.write("This documentation contains all the commands available in the dAngr debugger.\n\n")
        f.write("## Debugger Commands\n")
        package = None
        for name, obj in DEBUGGER_COMMANDS.items():
            cmd = obj(None)
            if package != DEBUGGER_COMMANDS[name].__module__.split('.')[-2]:
                package = DEBUGGER_COMMANDS[name].__module__.split('.')[-2]
                f.write(f"\n### {package}:\n")
            
            f.write(f"* `{get_cmd_name(obj)}`  (short: `{get_short_cmd_name(obj)}`)  \n")
            info = str(cmd.info).replace("\n", "\n" + " "*4)
            f.write(f"  {info}  \n")
            if cmd.arg_specs:
                args = ', '.join([f"{a[0].replace(' ', '_')} ({a[1].__name__ if a[1] else 'any'})"  for a in cmd.arg_specs])
                f.write(f"  - arguments: {args}  \n")
            if cmd.optional_args:
                optional_args = ', '.join([f"{a[0].replace(' ', '_')} ({a[1].__name__ if a[1] else 'any'})"  for a in cmd.optional_args])
                f.write(f"  - optional arguments: {optional_args}  \n")
            example = cmd.get_example()
            if example:
                f.write(f"  \n  Example: `{example}`  \n")
            f.write("\n")
        f.write("\n")
    print("Documentation generated successfully.")

document_gen()