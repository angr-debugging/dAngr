from dAngr.cli.filters import AddressFilter
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand

class EnableBreakpointCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [ ("address",int)]
        self.info = "Enable a breakpoint at address."

    async def execute(self, address):
        b = next((d for d in self.debugger.breakpoints if isinstance(d, AddressFilter) and d.address == address), None)
        if not b:
            raise DebuggerCommandError(f"No breakpoint found at address {hex(address)}.")
        b.enabled = True
        await self.send_info( f"Breakpoint enabled at address {hex(address)}.")

