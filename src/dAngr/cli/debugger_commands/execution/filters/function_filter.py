from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter, FunctionFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError


class FunctionFilterCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("function name",str)]
        self.optional_args = [("avoid",bool),("add",bool)]
        self.info = "Ignore paths part of a function with specified name."

    async def execute(self, name:str,avoid:bool=False, add:bool = True): # type: ignore
        #check if the functions exist
        if self.debugger.get_function_address(name) is None:
            raise DebuggerCommandError(f"Function {name} not found.")
        list = self.debugger.exclusions if avoid else self.debugger.breakpoints
        if not add:
            list = [f for f in list if not isinstance(f, FunctionFilter) or f.function_name != name]
        else:
            list.append(FunctionFilter(name))
        await self.send_info(f"Function {name} {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")