from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import AddressFilter
from dAngr.exceptions import DebuggerCommandError, ExecutionError


class AddressFilterCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("address",int)]
        self.optional_args = [("avoid",bool),("add",bool)]
        self.info = "Ignore paths containing address."
        
    async def execute(self, address:int, avoid:bool=False, add:bool = True): # type: ignore
        #if not add:
        list = self.debugger.exclusions if avoid else self.debugger.breakpoints
        if not add:
            list = [f for f in list if not isinstance(f, AddressFilter) or f.address != address]
        else:
            list.append(AddressFilter(address))
        await self.send_info(f"Address {hex(address)} {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")


