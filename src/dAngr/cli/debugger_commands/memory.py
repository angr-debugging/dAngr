import claripy
from dAngr.cli.grammar.execution_context import Variable
from dAngr.cli.grammar.expressions import ReferenceObject
from dAngr.cli.models import Register
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from dAngr.utils import  DataType, SymBitVector, SymString
from .base import BaseCommand


class MemoryCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)


    async def assign(self, target:Variable, value:int|bytes|str|SymBitVector|SymString|Variable):
        """
        Assign a value to some target symbol

        Args:
            target (Variable): Name of the symbol. Prefix with $reg for register, $mem for memory, $sym for symbol.
            value (int|bytes|str|SymBitVector|SymString|Variable): Value to set. Either a value or a prefixed register, memory or symbol.
        
        Short name: as
        
        """
        target.value = self.to_value(value)
        await self.send_info(f"Value {value} assigned to {target}.")


    async def add_to_stack(self, value:int|bytes|str|SymBitVector|SymString|Variable):
        """
        Add a value to the stack.

        Args:
            value (int|bytes|str|SymBitVector|SymString|Variable): Value to set at the stack.
        
        Short name: ast
        
        """
        self.debugger.add_to_stack(self.to_value(value))
        await self.send_info(f"Value {value} added to the stack.")

    async def get_stack(self, length:int, offset:int=0):
        """
        Get the stack values.

        Args:
            length (int): Length of the stack.
            offset (int): Offset from the current stack pointer. Default is 0.

        Short name: gst
        
        """
        return self.debugger.get_stack(length, offset)

    async def get_memory_string(self, address:int):
        """
        Get the memory value at a specific address.

        Args:
            address (int): Address in the memory
        
        Short name: mgs
        
        """
        return self.debugger.get_string_memory(address)
        
    async def get_memory(self, address:int, size:int, type:DataType = DataType.bytes):
        """
        Get the memory value at a specific address.
        Supported Types: int, bytes, bool, double, hex.

        Args:
            address (int): Address in the memory
            size (int): Size of the memory
        
        Short name: mg
        
        """
        m = self.debugger.get_memory(address, size)
        if m.symbolic:
            return str(m)
        value = self.debugger.cast_to(m, cast_to=type)
        if value:
            return value
        else:
            raise DebuggerCommandError(f"Invalid data type: {type}.")
    
    async def set_memory(self, address:int, value:str|bytes|int|SymBitVector|SymString|Variable):
        """
        Set a memory value at a specific address.
        Supported Types: int, str, bytes.

        Args:
            address (int): Address in the memory
            value (int|bytes|str|SymBitVector|SymString|Variable): Value to set at the address.

        Short name: ms
        """
        value = self.to_value(value)
        self.debugger.set_memory(address, value)        
        await self.send_info(f"Memory at {hex(address)}: {value}.")
    
    
    async def set_register(self, name:str, value:int|SymBitVector|Variable):
        """
        Set a register value. Same as $reg.{name} = {value}.

        Args:
            name (str): Register name
            value (int|SymBitVector|Variable): Value to set at the register.
        
        Short name: rs
        
        """
        self.debugger.set_register(name, self.to_value(value)) # type: ignore
        await self.send_info(f"Register {name}: {hex(value) if isinstance(value, int) else value}.")
    
    # async def set_register_to_symbol(self, name:str, value:Variable):
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
    #     await self.send_info(f"Register {name}: {value}.")

    async def get_register(self, name:str):
        """
        Get a register value, same as $reg.{name}.

        Args:
            name (str): Register name
        
        Short name: rg
        
        """
        value = self.debugger.get_register(name)
        return self.debugger.cast_to(value, cast_to=DataType.hex)

    async def list_registers(self):
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
        
        return  f"{"\n".join([str(r) for r in regs])}"

    async def zero_fill(self, enable:bool=True):
        """
        Fill the memory and registers with zero.

        Args:
            enable (bool): Enable or disable zero fill.
        
        Short name: zf
        
        """
        await self.debugger.zero_fill(enable)
        await self.send_info( f"Zero fill {'enabled' if enable else 'disabled'}.")
