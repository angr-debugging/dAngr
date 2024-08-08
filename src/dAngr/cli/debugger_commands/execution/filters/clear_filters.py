from ...base import BaseCommand

class ClearFiltersCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.optional_args = [("exclusions",bool)]
        self.info = "Remove all breakpoints. If exclusions is set (default: False), remove all exclusions instead."
        
    async def execute(self, exclusions:bool=False):
        # Find and remove the breakpoint
        if exclusions:
            self.debugger.exclusions.clear()
            await self.send_info( "All exclusions cleared.")
        else:
            self.debugger.breakpoints.clear()
            await self.send_info( "All breakpoints cleared.")
