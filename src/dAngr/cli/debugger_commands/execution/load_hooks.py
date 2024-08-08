from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import DebuggerCommandError, ExecutionError

class LoadHooksCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("filename",str)]
        self.info = "Load a python file containing SimProcedures as hooks."

    async def execute(self, filename):
        self.debugger.load_hooks(filename)
        await self.send_info(f"Hooks '{filename}' successfully attached.")
        

