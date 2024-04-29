from dAngr.cli.models import Response,State
from dAngr.cli.debugger_commands import BaseCommand

class SelectPathCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("index",int)]
        self.info = "Select the next path to take by index."

    async def execute(self, index):
        self.throw_if_not_initialized()
        state = self.debugger.select_active_path(index)
        return Response(State(index, state.addr))

