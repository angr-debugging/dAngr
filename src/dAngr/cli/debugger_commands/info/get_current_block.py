from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class GetCurrentBlockCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Show the assembly for the current basic block."
        
    async def execute(self): 
        b = self.debugger.get_current_basic_block()
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return f"Current basic block: {b}"

