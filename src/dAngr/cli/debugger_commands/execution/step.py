
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.exceptions import ExecutionError


class StepCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Take a next debugging step."
    
    async def execute(self):
        self.throw_if_not_active()
        await self.run(lambda:True)

