from dAngr.cli.models import BasicBlock
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from prompt_toolkit.shortcuts import ProgressBar

class GetBasicblocksCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Show the assembly for the current basic block."
        
    async def execute(self):
        with ProgressBar(title="reconstructing basic blocks") as pb:
            for b in pb(self.debugger.get_bbs()):
                await self.send_result(str(b))



