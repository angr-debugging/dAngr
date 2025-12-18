from dAngr.angr_ext.debugger import Debugger
from dAngr.dAngr_mcp.tools import McpCommand
from dAngr.utils.utils import DataType


class SymbolMCPCommand(McpCommand):
    def __init__(self, debugger:Debugger, mcp):
        super().__init__(debugger, mcp)

    def evaluate(self, symbol_name:str):
        """
        Evaluate a symbol and get the value.

        Args:
            symbol_name (str): name of the symbol to evaluate.    
        """
        if symbol_name.startswith('&sym.'):
            symbol_name = symbol_name[5:]
        
        sym = self.debugger.get_symbol(symbol_name)
        return self.debugger.eval_symbol(sym, DataType.bytes)