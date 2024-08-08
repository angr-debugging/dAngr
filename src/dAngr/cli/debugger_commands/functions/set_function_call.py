import angr
import re

from dAngr.angr_ext.utils import convert_string
from dAngr.utils.utils import parse_arguments
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class SetFunctionCallCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("function call",str)]
        self.info = "Initialize the function based on the previously pased prototype with the arguments.\n Example: void myfunc(\"txt\", 10)"
    
    async def execute(self, args):
        # TODO: clean this up
        pattern = r'(\w+)\((.*?)\)'
        match = re.match(pattern, args.strip())
        
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
            arguments=[]
            ix = 0
            for value in arg_strs:
                value = value.strip()
                tp = prototype.args[ix]
                v = convert_string(tp, value)
                ix = ix +1
                if type(tp) is angr.types.SimTypePointer:
                    v = 0x1000*ix
                arguments.append(v)

            state = self.debugger.get_function_callstate(function_name, prototype, cc, arguments)
            self.debugger.set_current_function(function_name)
            ix = 0
            info = []
            for value in vals_str.split(','):
                value = value.strip()
                tp = prototype.args[ix]
                v = convert_string(tp, value)
                ix = ix +1
                if type(tp) is angr.types.SimTypePointer:
                    self.debugger.set_memory(0x1000*ix,v,state)
                    v = 0x1000*ix
                    info.append(f"Value {value} stored at {hex(v)}")
            
        except Exception as e:
            raise DebuggerCommandError(f"Error setting up function call: {e}")

        await self.send_info(f"Function setup at {hex(addr)} with memory:{info}")
    
