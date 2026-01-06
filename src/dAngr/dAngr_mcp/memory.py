from dAngr.dAngr_mcp.tools import McpCommand


class MemoryMCPCommand(McpCommand):
    def __init__(self, debugger, mcp):
        super().__init__(debugger, mcp)
    
    def set_register(self, name:str, value:str):
        """
        Set a register value. Same as $reg.{name} = {value}.

        Args:
            name (str): Register name
            value (int|str: Value to set at the register. Can be a hex string (0x123), an integer (123), 
                     or a symbol name (&sym.name).
        
        Short name: rs
        
        """
        if value.startswith("0x"):
            val = int(value, 16)
        elif value.isdigit():
            val = int(value)
        elif value.startswith("&sym"):
            val = self.debugger.find_symbol(value[5:])
        
        self.debugger.set_register(name, val) # type: ignore
        self.send_info(f"Register {name}: {hex(value) if isinstance(value, int) else value}.")