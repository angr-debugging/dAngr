import claripy
from dAngr.exceptions import DebuggerCommandError
from dAngr.angr_ext.utils import Constraint, DataType, SolverType, SymBitVector, undefined, AngrType
from .base import BaseCommand

class SymbolCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    def add_symbol(self, name:str, size:int = 0, dtype:DataType = DataType.bytes):
        """
        Add a symbol of bytes with name and size.

        Args:
            name (str): Name of the symbol
            size (int): Size of the symbol
            dtype (DataType): type of the data, default is bytes.
        
        Short name: sa
        
        """
        if dtype == DataType.int:
            int_size = self.debugger.project.arch.sizeof["int"]
        else: int_size = size
        self.debugger.add_symbol(name, claripy.BVS(name, int_size*8))
        self.send_info(f"Symbol {name} created.")
        return self.debugger.get_symbol(name)
        
    def get_symbol (self, name:str):
        """
        Get a symbol by name.

        Args:
            name (str): Name of the symbol
        
        Short name: sym
        
        """
        return self.debugger.get_symbol(name)
    
    def chop_symbol(self, sym:str|SymBitVector, bits:int=1):
        """
        Chop a symbol to a specific number of bits.

        Args:
            sym (str|SymBitVector): Name of the symbol
            bits (int): Number of bits to chop
        
        Short name: cs
        
        """
        if isinstance(sym, str):
            sym = self.debugger.get_symbol(sym)
        return sym.chop(bits)
    
    def to_symbol(self, sym:str, list:list):
        """
        Concat items in list into a single symbol
        
        Args:
            sym (str): name of the symbol
            list (list): list of items
        """
        self.debugger.to_symbol(sym, list)
    
    def evaluate(self, sym:SymBitVector|str, dtype:DataType=DataType.bytes):
        """
        Evaluate a symbol and get the value.

        Args:
            sym (SymBitVector|str): Symbol to evaluate.
            dtype (DataType): Type of the symbol. Default is none.
        
        Short name: ev
        
        """
        if isinstance(sym, str):
            sym = self.debugger.get_symbol(sym)
        return self.debugger.eval_symbol(sym, dtype)
    
    def evaluate_n(self, sym:SymBitVector|str, n:int,  solve_info:SolverType=SolverType.UpTo,dtype:DataType=DataType.bytes):
        """
        Evaluate all symbols and get their values.

        Args:
            sym (SymBitVector|str): Symbol to evaluate.
            n (int): Number of symbols to evaluate.
            solve_info (SolverType): Type of the solver method. Default is UpTo. Possible Values: UpTo, AtLeast, Exact
            dtype (DataType): Type of the symbol. Default is none.
        
        Short name: eva
        
        """
        if isinstance(sym, str):
            sym = self.debugger.get_symbol(sym)
        return self.debugger.eval_symbol_n(sym, n, solve_info, dtype)
    
    def satisfiable(self, constraint:Constraint|None = None):
        """
        Check if the current state is satisfiable.

        Args:
            constraint (Constraint|None): Constraint to check. Default is None.
        
        Short name: sf
        
        """
        if constraint is None:
            return self.debugger.satisfiable()
        return self.debugger.satisfiable(constraint)
    def is_symbolic(self, sym:AngrType):
        """
        Check if a symbol is symbolic.

        Args:
            sym (AngrType): Name of the symbol
        
        Short name: sis
        
        """
        if isinstance(sym, str):
            sym = self.debugger.get_symbol(sym)
        if not isinstance(sym, SymBitVector):
            return False
        return self.debugger.is_symbolic(sym)
    # def add_symbol_int(self, name:str):
    #     """
    #     Add a symbol with name and size.

    #     Args:
    #         name (str): Name of the symbol
        
    #     Short name: sai
        
    #     """
    #     int_size = self.debugger.project.arch.sizeof["int"]
    #     self.debugger.add_symbol(name, claripy.BVS(name, int_size*8))
    #     self.send_info(f"Symbolic integer {name} created.")

    # def add_symbolic_string(self, name:str, size:int):
    #     """
    #     Add a symbol with name and size.

    #     Args:
    #         name (str): Name of the symbol
    #         size (int): Size of the symbol.
        
    #     Short name: sas
        
    #     """
    #     self.send_info(f"Symbolic string {name} created.")

    # def symbol_to_bytes(self, sym:str|SymBitVector):
    #     """
    #     Solve and get concrete symbol value in bytes based on current state.

    #     Args:
    #         sym (str|SymBitVector): Name of the symbol
        
    #     Short name: stb
        
    #     """
    #     if isinstance(sym, str):
    #         sym = self.debugger.get_symbol(sym)
    #     return self.debugger.cast_to(sym, DataType.bytes)
    
    # def symbol_to_int(self, sym:str|SymBitVector):
    #     """
    #     Solve and get concrete symbol value as int based on current state.

    #     Args:
    #         sym (str|SymBitVector): Name of the symbol
        
    #     Short name: sti
        
    #     """
    #     if isinstance(sym, str):
    #         sym = self.debugger.get_symbol(sym)
    #     return self.debugger.cast_to(sym, DataType.int)
    
    # def symbol_to_str(self, sym:str|SymBitVector):
    #     """
    #     Convert symbol to a str.

    #     Args:
    #         sym (str|SymBitVector): Name of the symbol
        
    #     Short name: sts
        
    #     """
    #     if isinstance(sym, str):
    #         sym = self.debugger.get_symbol(sym)
    #     return self.debugger.cast_to(sym, DataType.str)
    
    # def symbol_to_bool(self, sym:str|SymBitVector):
    #     """
    #     Solve and get concrete symbol value as bool based on current state.

    #     Args:
    #         sym (str|SymBitVector): Name of the symbol
        
    #     Short name: stB
        
    #     """
    #     if isinstance(sym, str):
    #         sym = self.debugger.get_symbol(sym)
    #     return self.debugger.cast_to(sym, DataType.bool)
    
    def remove_symbol(self, sym:str|SymBitVector):
        """
        Remove a symbol.

        Args:
            sym (str|SymBitVector): Name of the symbol
        
        Short name: sr
        
        """
        if isinstance(sym, SymBitVector):
            if len(sym.args) == 0:
                raise DebuggerCommandError("Symbol name not found.")
            name = sym.args[0]
        else: name = sym
        self.debugger.remove_symbol(name)
        self.send_info(f"Symbol {sym} removed.")
    
    # def set_symbol_value(self, sym:str|SymBitVector, value:int|bytes|str|SymBitVector):
    #     """
    #     Set a symbol value.

    #     Args:
    #         sym (str|SymBitVector): Name of the symbol
    #         value (int|bytes|str|SymBitVector): Value to set
        
    #     Short name: ssv
        
    #     """
    #     if isinstance(sym, str):
    #         sym = self.debugger.get_symbol(sym)
    #     value = self.to_value(value)
    #     self.debugger.set_symbol(sym, value)
    #     self.send_info(f"Symbol {sym} set to {value}.")

    def add_constraint(self, constraint:Constraint):
        """
        Add a constraint to a symbol.

        Args:
            constraint (Constraint): Constraint to add.
        
        Short name: sac
        
        """
        self.debugger.add_constraint(constraint)
        self.send_info(f"Constraint added.")
 