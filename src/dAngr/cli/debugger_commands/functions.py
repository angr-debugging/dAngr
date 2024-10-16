import re

import angr
from dAngr.angr_ext.utils import convert_string
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError
from dAngr.utils.utils import parse_arguments,Endness

class FunctionCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        
    async def get_return_value(self):
        """
        Get the return value after running the function.

        Returns:
            str: The return value of the function.

        Short name: fgr
        """
        val = self.debugger.get_return_value() 
        return str(val) if not val is None else ""

    async def set_call_state(self, function_addr: int, *args):
        """
        Set the call state of a function.

        Args:
            function_addr (int): The address of the function.
            args (tuple): Arguments to the function.

        Raises:
            DebuggerCommandError: If the function address is not found.
        
        Short name: scs
        """
        self.debugger.set_call_state(function_addr, args)
        await self.send_info(f"Call state set for function at {hex(function_addr)}")

    async def set_function_call(self, function_call: str):
        """
        Set the prototype of a function.

        Args:
            function_call (str): C-style function call with arguments.

        Raises:
            DebuggerCommandError: If the function signature format is invalid or if the function address is not found.
        
        Short name: fsc
        """
        # TODO: clean this up
        pattern = r'(\w+)\((.*?)\)'
        match = re.match(pattern, function_call.strip())
        
        if not match:
            raise DebuggerCommandError("Invalid function signature format.")
        
        function_name, vals_str = match.groups()
        func = self.debugger.get_stored_function(function_name)

        if func and "prototype" in func:
            prototype = func["prototype"]
            addr = self.debugger.get_function_address(function_name)
            if addr is None:
                raise DebuggerCommandError(f"Function address not found for {function_name}")
            cc = self.debugger.get_function_cc()
            self.debugger.store_function(function_name, prototype, addr, cc)
        else:
            raise DebuggerCommandError("Prototype not properly initialized, use SetFunctionPrototype command first")
        try:
            arg_strs = parse_arguments(vals_str, ",")
            # base_state = self.debugger.get_current_state()
            arguments = []
            ix = 0
            for value in arg_strs:
                value = value.strip()
                tp = prototype.args[ix]
                v = convert_string(tp, value)
                ix = ix + 1
                if type(tp) is angr.types.SimTypePointer and not type(v) is int:
                    v = 0x1000 * ix
                arguments.append(v)

            state = self.debugger.get_function_callstate(function_name, prototype, cc, arguments)
            self.debugger.set_current_function(function_name)
            ix = 0
            info = []
            for value in vals_str.split(','):
                value = value.strip()
                tp = prototype.args[ix]
                v = convert_string(tp, value)
                ix = ix + 1
                if type(tp) is angr.types.SimTypePointer and not type(v) is int:
                    self.debugger.set_memory(0x1000 * ix, v, len(v)) # type: ignore
                    v = 0x1000 * ix
                    info.append(f"Value {value} stored at {hex(v)}")
            
        except Exception as e:
            raise DebuggerCommandError(f"Error setting up function call: {e}")

        await self.send_info(f"Function setup at {hex(addr)} with memory:{info}")
    
    async def set_function_prototype(self, prt:str):
        """
        Set the prototype of a function.

        Args:
            prt (str): Prototype of the function.

        Raises:
            InvalidArgumentError: If the function signature format is invalid.
        
        Short name: fsp
        """
        # Define regex pattern for parsing function signature
        pattern = r'(.*)\s+(\w+)\s*\((.*?)\)'
        match = re.match(pattern, prt.strip())
        if not match:
            raise InvalidArgumentError("Invalid function signature format.")

        return_type, function_name, args_str = match.groups()
        self.debugger.set_function_prototype(return_type, function_name, args_str.split(','))

        await self.send_info(f"Function signature set for {function_name}")



    async def decompiled_function(self, function:str):  # type: ignore
        """
        Show the decompiled function.

        Args:
            function (str): The name of the function.

        Returns:
            str: The decompiled function.

        Raises:
            DebuggerCommandError: If no function is found with the given name.
        
        Short name: fd
        """
        b = self.debugger.get_decompiled_function(function)
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return f"{b}"
    
    

    async def decompiled_function_at_address(self, address:int, end:int):  # type: ignore
        """
        Show the decompiled function at a given address.

        Args:
            address (int): The address to decompile the function at.
            end (int): The end address of the function.

        Returns:
            str: The decompiled function.

        Raises:
            DebuggerCommandError: If no function or basic block is found at the given address.
        Short name: fda
        """
        # func = address
        # func = self.debugger.get_function_info(address)
        # if func is None:
        #     raise DebuggerCommandError("No function found at this address.")
        b = self.debugger.get_decompiled_function_at_address(address, end)
        if b is None:
            raise DebuggerCommandError("No basic block found.")
        return f"{b}"

    async def get_function_info(self, function_name: str):
        """
        Get information about a function.

        Args:
            function_name (str): The name of the function.

        Returns:
            str: Information about the function.

        Raises:
            DebuggerCommandError: If no function is found with the given name.
        
        Short name: fi
        """
        func = self.debugger.get_function_info(function_name)
        if func is None:
            raise DebuggerCommandError("No function found with this name.")
        return f"{func}"
    
