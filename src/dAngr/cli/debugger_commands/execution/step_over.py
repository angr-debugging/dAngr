
from dAngr.angr_ext.step_handler import StopReason
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.exceptions import ExecutionError


class StepOverCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Take a next debugging step."
    
    async def execute(self): # type: ignore        
        cs0 = self.debugger.get_callstack()
        def check_call_stack(_)->StopReason:
            cs = self.debugger.get_callstack()
            if len(cs)!= len(cs0):
                return StopReason.NONE
            for i in range(0,len(cs)):
                if cs[i]['func']!= cs0[i]['func']:
                    return StopReason.NONE
            return StopReason.STEP

        await self.run(check_call_stack) # return immediately

