import claripy
from dAngr.utils.utils import Constraint, DataType, SymBitVector, SymString, undefined
from .base import BaseCommand

class SymbolCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    async def add_symbolic_bitvector(self, name:str, size:int):
        """
        Add a symbol of bytes with name and size.

        Args:
            name (str): Name of the symbol
            size (int): Size of the symbol.
        
        Short name: sab
        
        """
        self.debugger.add_symbol(name, claripy.BVS(name, size*8))
        await self.send_info(f"Symbolic bitvector {name} created.")

    
    async def add_symbol_int(self, name:str):
        """
        Add a symbol with name and size.

        Args:
            name (str): Name of the symbol
        
        Short name: sai
        
        """
        int_size = self.debugger.project.arch.sizeof["int"]
        self.debugger.add_symbol(name, claripy.BVS(name, int_size*8))
        await self.send_info(f"Symbolic integer {name} created.")

    async def add_symbolic_string(self, name:str, size:int):
        """
        Add a symbol with name and size.

        Args:
            name (str): Name of the symbol
            size (int): Size of the symbol.
        
        Short name: sas
        
        """
        self.debugger.add_symbol(name, claripy.StringS(name, size*8))
        await self.send_info(f"Symbolic string {name} created.")
    
    async def get_symbolic_value(self, sym:str|SymBitVector|SymString, type:DataType = DataType.bytes):
        """
        Get a symbol with name.

        Args:
            sym (str|SymBitVector|SymString): Name of the symbol
            type (DataType): Type of the symbol. Default is bytes.
        
        Short name: sg
        
        """
        if isinstance(sym, str):
            sym = self.debugger.get_symbol_value(sym)
        return self.debugger.cast_to(sym, type)

    async def add_constraint(self, constraint:Constraint):
        """
        Add a constraint to a symbol.

        Args:
            constraint (Constraint): Constraint to add.
        
        Short name: sc
        
        """
        self.debugger.add_constraint(constraint)
        await self.send_info(f"Constraint {constraint} added.")
 