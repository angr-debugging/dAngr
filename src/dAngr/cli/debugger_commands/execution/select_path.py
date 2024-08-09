from dAngr.cli.models import State
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class SelectPathCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("index",int, "The index of the path to select as shown in list_active_paths.")]
        self.info = "Select the next path to take by index."

    async def execute(self, index):
        state = self.debugger.select_active_path(index)
        if state is None:
            raise DebuggerCommandError("Invalid path index specified.")
        await self.send_info(f"Path {index} selected: {hex(state.addr)}")

