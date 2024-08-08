
from dAngr.angr_ext.step_handler import StopReason
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.exceptions import ExecutionError


class StepOutCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Step out of current function."
        self.short_cmd_name = "sO"
    
    async def execute(self):  # type: ignore
        cs0 = self.debugger.get_callstack()
        def check_call_stack(_)->StopReason:
            cs = self.debugger.get_callstack()
            if len(cs) < len(cs0):
                return StopReason.STEP
            return StopReason.NONE

        await self.run(check_call_stack) # return immediately

