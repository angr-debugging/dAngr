from dAngr.cli.models import State
from ..base import BaseCommand

class ListActivePathsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List the active paths."

    async def execute(self): # type: ignore
        paths = self.debugger.get_paths()
        
        return f"Paths Found: {"\n".join( [str(State(index, path.addr)) for index, path in enumerate(paths)])}"

