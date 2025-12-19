from dAngr.angr_ext.debugger import Debugger
from dAngr.dAngr_mcp.tools import McpCommand
from dAngr.utils.utils import DataType, Operator


class SymbolMCPCommand(McpCommand):
    def __init__(self, debugger:Debugger, mcp):
        super().__init__(debugger, mcp)

    def __find_symbol(self, symbol_name:str):
        if symbol_name.startswith('&sym.'):
            symbol_name = symbol_name[5:]
        
        return self.debugger.get_symbol(symbol_name)

    def _resolve_symbol_or_addr(self, to_resolve:str, size:int|None=None):
        if to_resolve.startswith('&sym.'):
            inpt = self.__find_symbol(to_resolve)
            if size is not None:
                inpt = inpt[size]
        elif to_resolve.startswith('0x'):
            if size is None:
                raise ValueError('Size is required when using memory addresses')
            mem_addr = int(to_resolve, 16)
            inpt = self.debugger.get_memory(mem_addr, size)
        elif to_resolve.isdigit():
            if size is None:
                raise ValueError('Size is required when using memory addresses')
            mem_addr = int(to_resolve)
            inpt = self.debugger.get_memory(mem_addr, size)
        
        return inpt


    def evaluate(self, to_eval:str, size:int|None=None):
        """
        Evaluate a symbol and get the value.

        Args:
            to_eval (str): name of the symbol or address to evaluate (addresses can be in int (123) or hex (0x7B)). 
            size (int|None): the size of memory that has to be evaluated, only required when providing an address.   
        """
        
        sym = self._resolve_symbol_or_addr(to_eval, size)
        return self.debugger.eval_symbol(sym, DataType.bytes)
    
    def add_constraint(self, to_constrain:str, value:str, operator:str, size:int|None=None):
        """
        Add a constraint to a symbol.

        Args:
            to_constrain (str): name of the symbol or address to constrain (address can be an int or hex string). Note address requires a size.
            value (str): The value to constrain the symbol to. Can be a decimal integer (e.g. "123"), a hex string (e.g. "0x123"), or a negative integer.
            operator (str): operator to use for the constraint (e.g. "==", "!=", ">", "<").
            size (int, optional): this can be the size of the memory or the index of a symbol. Both size of memory and index of a symbol will be per byte.
        
        Example:
            add_constraint('&sym.input', '0x41', '==', 1)
            add_constraint('0x7ffffffffffefef', '0x41414141', '==', 4)
        """

        inpt = self._resolve_symbol_or_addr(to_constrain, size)        
        # Find the operator enum
        op_enum = next((op for op in Operator if str(op) == operator), None)
        if not op_enum:
            raise ValueError(f"Unsupported operator: {operator}")
            
        magic_method = Operator.convert_to_magic_method(op_enum)
        if not magic_method:
             raise ValueError(f"Operator {operator} cannot be converted to a magic method")
        
        # Convert value
        val = value
        if isinstance(value, str):
            if value.startswith("0x"):
                val = int(value, 16)
            elif value.isdigit():
                val = int(value)
            elif value.startswith("-") and value[1:].isdigit():
                val = int(value)
        
        constraint = getattr(inpt, magic_method)(val)
        self.debugger.add_constraint(constraint)

        