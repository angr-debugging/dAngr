
import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError


class RunScriptCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("script path", str)]
        self.info = "Run dAngr script."
        self.short_cmd_name = "rs"

    async def execute(self, script_path:str):
        # read the script and call handler for each non-empty, non-comment line
        try:
            print(os.getcwd())
            with open(script_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        await self.debugger.handle(line)
        except Exception as e:
            raise DebuggerCommandError(f"Failed to run script: {e}")

