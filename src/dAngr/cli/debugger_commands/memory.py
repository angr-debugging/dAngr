import claripy
from dAngr.angr_ext.execution_context import Variable
from dAngr.angr_ext.expressions import ReferenceObject
from dAngr.cli.models import Register
from dAngr.angr_ext.utils import  SymBitVector, AngrType, Endness
from .base import BaseCommand


class MemoryCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)


    def assign(self, target:ReferenceObject, value:int|bytes|str|SymBitVector|Variable):
        """
        Assign a value to some target symbol

        Args:
            target (ReferenceObject): Name of the symbol. Prefix with &reg for register, &mem for memory, &sym for symbol.
            value (int|bytes|str|SymBitVector|Variable): Value to set. Either a value or a prefixed register, memory or symbol.
        
        Short name: as
        
        """
        target.set_value(self.debugger.context,self.to_value(value))
        self.send_info(f"Value {value} assigned to {target}.")


    def add_to_stack(self, value:int|bytes|str|SymBitVector|Variable):
        """
        Add a value to the stack.

        Args:
            value (int|bytes|str|SymBitVector|Variable): Value to set at the stack.
        
        Short name: ast
        
        """
        self.debugger.add_to_stack(self.get_angr_value(value))
        self.send_info(f"Value {value} added to the stack.")

    def get_stack(self, length:int, offset:int=0):
        """
        Get the stack values.

        Args:
            length (int): Length of the stack.
            offset (int): Offset from the current stack pointer. Default is 0.

        Short name: gst
        
        """
        return self.debugger.get_stack(length, offset)

    def get_memory_string(self, address:int):
        """
        Get the memory value at a specific address.

        Args:
            address (int): Address in the memory
        
        Short name: mgs
        
        """
        return self.debugger.get_string_memory(address)
        
    def get_memory(self, address:int|SymBitVector, size:int|SymBitVector, endness:Endness=Endness.DEFAULT):
        """
        Get the memory value at a specific address.
        Supported Conversion Types: int, bytes, bool, double, hex, none.

        Args:
            address (int): Address in the memory
            size (int): Size of the memory
            endness (Endness): Endianness of the value.
        
        Short name: mg
        
        """
        return self.debugger.get_memory(address, size, endness=endness)
    
    def get_addr_for_name(self, name: str):
        """
        Get the address for a symbol name.
        Requires the options REVERSE_MEMORY_NAME_MAP and TRACK_ACTION_HISTORY in the entry state. 

        Args:
            name (str): Symbol name
        
        Short name: gan
        
        """
        addresses = []
        for addr in self.debugger.get_addr_for_symbol(name):
            addresses.append(addr)
        return addresses

    def get_stdin_variables(self):
        """
        Get the stdin variable.

        Short name: gsv
        
        """
        stdin_vars = []
        for _, symbol in self.debugger.get_stdin_variables():
            stdin_vars.append(symbol)
        return stdin_vars
    
    def set_memory(self, address:int|SymBitVector, value:AngrType, size:int|None=None, endness:Endness=Endness.DEFAULT):
        """
        Set a memory value at a specific address.
        Supported Conversion Types: int, bytes, bool, double, hex, none.

        Args:
            address (int|SymBitVector): Address in the memory
            value (AngrType): Value to set at the address.
            size (int|None): Size of the memory, default is None.
            endness (Endness): Endianness of the value.

        Short name: ms
        """
        value = self.get_angr_value(value)
        self.debugger.set_memory(address, value, size=size, endness=endness)        
        if isinstance(address, SymBitVector):
            a = str(address)
        else:
            a = hex(address)
        self.send_info(f"Memory at {a}: {value}.")
    
    def add_static_pointer(self, name:str, value:int, size_bytes:int = 4):
        """
        Create a static pointer variable.

        Args:
            name (str): Name of the pointer
            value (int): pointer value.
            size_bytes (int): size of the variable in bytes, default 4.
        
        Short name: asp
        
        """
        val = claripy.BVV(value, size_bytes*8)
        self.debugger.context.add_variable(name, val)
        self.send_info(f"Pointer {name}: {value} added to variables.")
    
    def set_register(self, name:str, value:int|SymBitVector|Variable):
        """
        Set a register value. Same as $reg.{name} = {value}.

        Args:
            name (str): Register name
            value (int|SymBitVector|Variable): Value to set at the register.
        
        Short name: rs
        
        """
        self.debugger.set_register(name, self.to_value(value)) # type: ignore
        self.send_info(f"Register {name}: {hex(value) if isinstance(value, int) else value}.")
    
    # def set_register_to_symbol(self, name:str, value:Variable):
    #     """
    #     Set a register value to a symbol.

    #     Args:
    #         name (str): Register name
    #         value (Variable): Symbol name to set at the register.
        
    #     Short name: rss
        
    #     """
        
    #     v = self.debugger.get_new_symbol_object(value)
    #     if isinstance(v, claripy.ast.FP) or isinstance(v, claripy.ast.String):
    #         raise ValueError("Symbol cannot be a floating point or string value.")
    #     self.debugger.set_register(name, v)
    #     self.send_info(f"Register {name}: {value}.")

    def get_register(self, name:str):
        """
        Get a register value, same as $reg.{name}.

        Args:
            name (str): Register name
        
        Short name: rg
        
        """
        return self.debugger.get_register(name)

    def list_registers(self):
        """
        List all the registers.

        Short name: rl
        
        """
        regs=[]
        registers = self.debugger.list_registers()
        for reg, (offset, size) in registers.items():
            # Reading register value; size is in bits, need to convert to bytes
            value = self.debugger.get_register_value(reg)
            regs.append(Register(reg,size,offset,value))
        
        return regs

    def unconstrained_fill(self, symbolic:bool=False):
        """
        Fill the memory and registers with symbolic values.

        Args:
            symbolic (bool): fill with symbolic values, else with zeros. Default is zeros.
        
        Short name: uf
        
        """
        self.debugger.unconstrained_fill(symbolic)
        self.send_info( f"Fill {'with symbols' if symbolic else 'with zeros'}.")
