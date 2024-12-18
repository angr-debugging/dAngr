class BasicBlock:
    def __init__(self,address, size, instructions, assembly, function=None):
        self.address = address
        self.size = size
        self.instructions = instructions
        self.assembly = assembly
        self.function = function
    def __str__(self) -> str:
        #add function name if function is not None
        f = f"  Function: {self.function}\n" if self.function else ""
        return f"Address: {hex(self.address)}:\n{f}  Size: {self.size} bytes\n  Number of Instructions: {self.instructions}\n  Disassembly:\n    {str(self.assembly).replace('\n','\n    ')}"


class DebugSymbol:
    def __init__(self,name,type,address):
        self.name = name
        self.type = type
        self.address = address if address != 'N/A' else None
    def __str__(self) -> str:
        if self.address:
            return f"Debug Symbol: {self.name} ({self.type}) at {hex(self.address)}"
        else:
            return f"Debug Symbol: {self.name} ({self.type})"
        
