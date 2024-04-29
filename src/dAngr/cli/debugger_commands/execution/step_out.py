
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.exceptions import ExecutionError


class StepOutCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Step out of current function."
    
    async def execute(self):
        self.throw_if_not_active()
        
        cs0 = self.debugger.get_callstack()
        def check_call_stack():
            cs = self.debugger.get_callstack()
            if len(cs) < len(cs0):
                return False
            for i in range(0,len(cs)):
                if cs[i]['func']!= cs0[i]['func']:
                    return False
            return True

        await self.run(check_call_stack) # return immediately

