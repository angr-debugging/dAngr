from ..base import BaseCommand

class ListBinarySymbolsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "List the debugsymbols when available."
        self.short_cmd_name = "lbsym"

    async def execute(self): # type: ignore
        symbols = self.debugger.get_binary_symbols()
        return f"Binary Symbols: {"\n".join([str(s) for s in symbols])}"
