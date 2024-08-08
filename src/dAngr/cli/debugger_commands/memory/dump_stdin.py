from  dAngr.cli.models import Memory
from ..base import BaseCommand

class DumpStdinCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Get contents of stdin passed to the binary to get at current state."

    async def execute(self):
        value = self.debugger.get_stdin()
        return value
