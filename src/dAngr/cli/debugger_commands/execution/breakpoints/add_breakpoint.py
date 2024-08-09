import os
from dAngr.cli.filters import BreakpointFilter
from dAngr.cli.models import Breakpoint
from dAngr.exceptions import ExecutionError
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from ...base import BaseCommand

class AddBreakpointCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("address",int,"Address to set the breakpoint at.")]
        self.info = "Set a breakpoint at a given address. If avoid is set, the breakpoint will be set to avoid the address."

    async def execute(self, address):  # type: ignore
        if any(bp.address == address for bp in self.debugger.breakpoints if isinstance(bp, BreakpointFilter)):
            raise DebuggerCommandError(f"Breakpoint already exists at {hex(address)}.")
        # get bb address from the address
        bp = BreakpointFilter(address)
        self.debugger.breakpoints.append(bp)
        await self.send_info(f"Breakpoint added and enabled at address {hex(address)}.")
    
