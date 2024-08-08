from ..base import BaseCommand

class GetRegisterCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [("name",str)]
        self.info = "Get a register value."
        self.short_cmd_name = "gr"

    async def execute(self, register):
        """Get a register value. Usage: get_register eax"""        
        size = self.debugger.get_register(register)[1]
        value = self.debugger.get_register_value(register, size)
        if value.concrete:
            value = hex(value.concrete_value)
        return f"{register}: {value}."

