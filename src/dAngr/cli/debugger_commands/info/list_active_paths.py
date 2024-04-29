from dAngr.cli.models import Response,State
from ..base import BaseCommand

class ListActivePathsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List the active paths."

    async def execute(self):
        self.throw_if_not_active()
        paths = self.debugger.get_paths()
        return Response([State(index, path.addr)for index, path in enumerate(paths)], "Paths Found: {self}")

