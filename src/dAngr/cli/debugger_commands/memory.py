from multimethod import multimethod
from dAngr.cli.models import Memory, Register
from dAngr.utils.utils import DataType, StreamType
from .base import BaseCommand

class MemoryCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)


    async def add_symbol(self, name:str, size:int):
        """
        Add a symbol with name and size.

        Args:
            name (str): Name of the symbol
            size (int): Bitsize of the symbol.
        
        Short name: sa
        
        """
        self.debugger.add_symbol(name, size)
            
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

    async def dump_stdstream(self, stream_type: StreamType = StreamType.stdout):
        """
        Dump the standard stream.

        Args:
            stream_type (StreamType): The type of the stream to dump. Default is stdout.
        
        Short name: ds
        
        """
        await self.send_info(self.debugger.get_stdstream(stream_type))


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
