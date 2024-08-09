from dAngr.cli.filters import AddressFilter, BreakpointFilter
from dAngr.cli.models import Breakpoint
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand

class DisableBreakpointCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [ ("address",int,"Address to disable the breakpoint at.")]
        self.info = "Disable breakpoint at index."

    async def execute(self, address):
        b = next((d for d in self.debugger.breakpoints if isinstance(d, AddressFilter) and d.address == address), None)
        if not b:
            raise DebuggerCommandError(f"No breakpoint found at address {hex(address)}.")
        b.enabled = False
        await self.send_info( f"Breakpoint disabled at address {hex(address)}.")

