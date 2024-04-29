from dAngr.cli.models import Response
import angr
from ..base import BaseCommand

class ZeroFillCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Enable or disable to fill memory and registers with zero values."
        self.optional_args = [("enable", bool)]

    async def execute(self, enable=True):
        """Enable or disable zero fill."""
        self.debugger.zero_fill(enable)
        return Response(f"Zero fill {'enabled' if enable else 'disabled'}.")
