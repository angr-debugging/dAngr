import claripy
from multimethod import multimethod
from dAngr.cli.models import Memory, Register
from dAngr.utils.utils import DataType, StreamType, convert_argument
from .base import BaseCommand

class SymbolCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    async def add_symbol(self, name:str, size:int):
        """
        Add a symbol of bytes with name and size.

        Args:
            name (str): Name of the symbol
            size (int): Size of the symbol.
        
        Short name: sab
        
        """
        self.debugger.add_symbol(name, {"size":size, "type":bytes})
    async def add_int_symbol(self, name:str, size:int):
        """
        Add a symbol with name and size.

        Args:
            name (str): Name of the symbol
            size (int): Size of the symbol.
        
        Short name: sai
        
        """
        self.debugger.add_symbol(name, {"size":size, "type":int})
    async def add_str_symbol(self, name:str, size:int):
        """
        Add a symbol with name and size.

        Args:
            name (str): Name of the symbol
            size (int): Size of the symbol.
        
        Short name: sas
        
        """
        self.debugger.add_symbol(name, {"size":size, "type":str})
    
    async def remove_symbol(self, name:str):
        """
        Remove a symbol with name.

        Args:
            name (str): Name of the symbol
        
        Short name: sr
        
        """
        self.debugger.remove_symbol(name)
    
    async def get_symbol(self, name:str, type:DataType = DataType.bytes):
        """
        Get a symbol with name.

        Args:
            name (str): Name of the symbol
            type (DataType): Type of the symbol. Default is bytes.
        
        Short name: sg
        
        """
        val = self.debugger.get_symbol(name)
        if val is None:
            await self.send_error(f"Symbol {name} not found.")
            return
        if val.concrete:
            cvalue = self.debugger.cast_to(val, type)
            await self.send_result(f"Symbol {name} is {cvalue}.")
        else:
            await self.send_result(f"Symbol {name} is {val}.")

    async def add_constraints(self, constraint:str):
        """
        Add a constraint to a symbol.

        Args:
            symbol (str): Name of the symbol
            constraint (str): Constraint to add.
        
        Short name: sc
        
        """
        sym = self.debugger.get_symbol(symbol)
        # parse constriant string to claripy constraint

        self.debugger.add_constraint(cs)