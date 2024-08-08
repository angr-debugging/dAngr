import re

from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError
from..base import BaseCommand

class SetFunctionPrototypeCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("prototype",str)]
        self.info = "Set the function prototype including name, argument types and return type.\n Example: void myfunc(char*, int)"
    
    async def execute(self, prt):
        # Define regex pattern for parsing function signature
        pattern = r'(.*)\s+(\w+)\s*\((.*?)\)'
        match = re.match(pattern, prt.strip())
        if not match:
            raise InvalidArgumentError("Invalid function signature format.")

        return_type, function_name, args_str = match.groups()
        self.debugger.set_function_prototype(return_type, function_name, args_str.split(','))

        await self.send_info(f"Function signature set for {function_name}")

