from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import DebuggerCommandError, ExecutionError

class LoadHooksCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("filename",str)]
        self.info = "Load a python file containing SimProcedures as hooks."
        self.extra_info = """
import angr

class printf(angr.SimProcedure): 
    def run(self, args): # type: ignore
        print(f"Running hooked print function in example_hooks.py: {args}")
        return None
"""
    async def execute(self, filename):
        self.debugger.load_hooks(filename)
        await self.send_info(f"Hooks '{filename}' successfully attached.")
        

