from ...base import BaseCommand

class ClearBreakpointsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Remove all breakpoints."
        
    async def execute(self):
        # Find and remove the breakpoint
        self.debugger.breakpoints.clear()
        await self.send_info( "All breakpoints cleared.")
