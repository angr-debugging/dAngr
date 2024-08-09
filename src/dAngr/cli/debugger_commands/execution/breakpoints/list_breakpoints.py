from ...base import BaseCommand

class ListBreakpointsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List all breakpoints."

    async def execute(self):
        if self.debugger.breakpoints.empty():
            await self.send_info("No breakpoints set.")
            return []
        return f"Breakpoint(s): {','.join([f'[{i}] {b}' for i,b in enumerate(self.debugger.breakpoints)])}"

