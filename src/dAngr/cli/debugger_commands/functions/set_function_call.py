import angr
import re

from dAngr.angr_ext.utils import convert_string, set_memory
from dAngr.cli.models import Response
from dAngr.exceptions import ExecutionError
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class SetFunctionCallCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("function call",str)]
        self.info = "Initialize the function based on the previously pased prototype with the arguments.\n Example: void myfunc(\"txt\", 10)"
    
    async def execute(self, args):
        self.throw_if_not_initialized()
        pattern = r'(\w+)\((.*?)\)'
        match = re.match(pattern, args.strip())
        
        if not match:
            return Response({}, "Invalid function signature format.")
        
        function_name, vals_str = match.groups()
        func = self.debugger.get_stored_function(function_name)

        if func and "prototype" in func:
            prototype = func["prototype"]
            addr = self.debugger.get_function_address(function_name)
            cc = self.debugger.get_function_cc()
            self.debugger.store_function(function_name, prototype, addr, cc)
        else:
            raise DebuggerCommandError("Prototype not properly initialized, use SetFunctionPrototype command first")
        try:
            arguments = []
            ix = 0
            for value in vals_str.split(','):
                value = value.strip()
                tp = prototype.args[ix]
                v = convert_string(tp, value)
                ix = ix +1
                if type(tp) is angr.sim_type.SimTypePointer:
                    v = 0x1000*ix
                arguments.append(v)

            self.debugger.init_function_call(addr, prototype, cc, arguments)
            self.debugger.set_current_function(function_name)
            ix = 0
            info = []
            for value in vals_str.split(','):
                value = value.strip()
                tp = prototype.args[ix]
                v = convert_string(tp, value)
                ix = ix +1
                if type(tp) is angr.sim_type.SimTypePointer:
                    self.debugger.set_memory(0x1000*ix,v)
                    v = 0x1000*ix
                    info.append(f"Value {value} stored at {hex(v)}")
            
        except Exception as e:
            raise DebuggerCommandError(f"Error setting up function call: {e}")

        return Response({"address":addr,"memory":"' ".join(info)}, f"Function setup at {hex(addr)} with memory:{info}")
    
