from dAngr.cli.models import DebugSymbol, Response
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class ListBinarySymbolsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List the debugsymbols when available.\n Requires DWARF info."

    async def execute(self):
        self.throw_if_not_initialized()
        symbols = self.debugger.get_binary_symbols()
        return Response(symbols,"Binary Symbols: {self}")
