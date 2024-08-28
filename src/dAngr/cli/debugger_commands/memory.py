import claripy
from multimethod import multimethod
from dAngr.cli.models import Memory, Register
from dAngr.utils.utils import DataType, StreamType, convert_argument
from .base import BaseCommand

class MemoryCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)


    async def assign(self, target:str, value:int|bytes|str):
        """
        Assign a value to some target

        Args:
            target (str): Name of the symbol. Prefix with $reg for register, $mem for memory, $sym for symbol.
            value (str): Value to set. Either a value or a prefixed register, memory or symbol.
        
        Short name: as
        
        """
        val = value
        if isinstance(value, int):
            val = self.debugger.to_bytes(value)
        elif isinstance(value, bytes):
            pass
        elif isinstance(value, str):
            if value.startswith("$"):
                t,v = value.split(".", 1)
                if t == "$reg":
                    val = self.debugger.get_register(int(v))
                elif t == "$mem":
                    val = self.debugger.get_memory(v)
                elif t == "$sym":
                    val = self.debugger.get_symbol(v)
                else:
                    raise ValueError("Invalid value. Use $reg, $mem or $sym.")
            else:
                val = self.debugger.to_bytes(value)
        if target.startswith("$") and "," in target:
            vv, n = target.split(".", 1)
            if vv == "$reg":
                if not isinstance(val, int) or not isinstance(n, claripy.ast.BV):
                    raise ValueError("Invalid value. Use an integer value or symbol.")
                self.debugger.set_register(n, val)
                await self.send_info(f"Register {n} set to {value}.")
            elif vv == "$mem":
                address = convert_argument(int, n)
                self.debugger.set_memory(address, val) # type: ignore
                await self.send_info(f"Memory at {n} set to {value}.")
            elif vv == "$sym":
                self.debugger.set_symbol(n, val)
                await self.send_info(f"Symbol {n} set to {value}.")
            else:
                await self.send_error("Invalid target. Use $reg, $mem or $sym.")
        else:
            raise ValueError("Invalid target. Use $reg, $mem or $sym.")

    async def add_to_stack(self, value:int|bytes|str):
        """
        Add a value to the stack.

        Args:
            value (int|bytes|str): Value to set at the stack.
        
        Short name: ast
        
        """
        val = value
        if isinstance(value, int):
            val = self.debugger.to_bytes(value)
        elif isinstance(value, bytes):
            pass
        elif isinstance(value, str):
            if value.startswith("$"):
                t,v = value.split(".", 1)
                if t == "$sym":
                    val = self.debugger.get_symbol(v)
                else:
                    raise ValueError("Invalid value. Use $sym.")
            else:
                val = self.debugger.to_bytes(value)
        self.debugger.add_to_stack(val)
        await self.send_info(f"Value {value} added to the stack.")


    async def get_memory_string(self, address:int):
        """
        Get the memory value at a specific address.

        Args:
            address (int): Address in the memory
        
        Short name: mgs
        
        """
        m = self.debugger.get_string_memory(address)
        return str(m)
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
            return str(value)
        else:
            raise ValueError(f"Invalid data type: {type}.")
    
    async def set_memory(self, address:int, value:str|bytes|int):
        """
        Set a memory value at a specific address.
        Supported Types: int, str, bytes.

        Args:
            address (int): Address in the memory
            value (int|bytes|str): Value to set at the address.

        Short name: ms
        """
        byte_value = self.debugger.to_bytes(value)
        self.debugger.set_memory(address, byte_value)
        await self.send_info(f"Memory at {hex(address)}: {byte_value}.")
    
    
    async def set_register(self, name:str, value:int):
        """
        Set a register value.

        Args:
            name (str): Register name
            value (int): Value to set at the register.
        
        Short name: rs
        
        """
        self.debugger.set_register(name, value)
        await self.send_info(f"Register {name}: {hex(value)}.")
    
    async def set_register_to_symbol(self, name:str, value:str):
        """
        Set a register value to a symbol.

        Args:
            name (str): Register name
            value (str): Symbol name to set at the register.
        
        Short name: rss
        
        """
        v = self.debugger.get_new_symbol_object(value)
        if isinstance(v, claripy.ast.FP) or isinstance(v, claripy.ast.String):
            raise ValueError("Symbol cannot be a floating point or string value.")
        self.debugger.set_register(name, v)
        await self.send_info(f"Register {name}: {value}.")

    async def get_register(self, name:str):
        """
        Get a register value.

        Args:
            name (str): Register name
        
        Short name: rg
        
        """
        size = self.debugger.get_register(name)[1]
        value = self.debugger.get_register_value(name, size)
        if value.concrete:
            value = hex(value.concrete_value)
        return f"{value}"

    async def list_registers(self):
        """
        List all the registers.

        Short name: rl
        
        """
        regs=[]
        registers = self.debugger.list_registers()
        for reg, (offset, size) in registers.items():
            # Reading register value; size is in bits, need to convert to bytes
            value = self.debugger.get_register_value(reg, size)
            regs.append(Register(reg,size,value))
        
        return  f"Registers and their current values:{" ".join([str(r) for r in regs])}"

    async def zero_fill(self, enable:bool=True):
        """
        Fill the memory and registers with zero.

        Args:
            enable (bool): Enable or disable zero fill.
        
        Short name: zf
        
        """
        await self.debugger.zero_fill(enable)
        await self.send_info( f"Zero fill {'enabled' if enable else 'disabled'}.")
