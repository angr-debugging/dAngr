from ..base import BaseCommand

class ListConstraintsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List the current path's constraints and symbolic variables."

    async def execute(self): # type: ignore
        """List the current path's constraints and symbolic variables."""
        
        ctrs = self.debugger.get_constraints()
        return f"Constraints: {"\n".join([str(c) for c in ctrs])}"

