from dAngr.cli.models import Memory
from ..base import BaseCommand

class AddSymbolCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("name",str,"Name of the symbol"),("size",int,"Bitsize of the symbol.")]
        self.info = "Add a symbol with name and size."


    async def execute(self, name, size):
        self.debugger.add_symbol(name, size)
            
