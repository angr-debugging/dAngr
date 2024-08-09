from dAngr.cli.filters import AddressFilter
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand

class RemoveBreakpointCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int,"Address to remove the breakpoint at.")]
        self.info = "Remove a breakpoint at specified address."
        
    async def execute(self, address:int):
        # Find and remove the breakpoint
        b = next((d for d in self.debugger.breakpoints if isinstance(d, AddressFilter) and d.address == address), None)
        if not b:
            raise DebuggerCommandError(f"No breakpoint found at address {hex(address)}.")
        self.debugger.breakpoints.remove(b)
        await self.send_info(f"Breakpoint removed at address {hex(address)}.")

