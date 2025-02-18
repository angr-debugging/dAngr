class BasicBlock:
    def __init__(self,address, size, instructions, assembly, function=None):
        self.address = address
        self.size = size
        self.instructions = instructions
        self.assembly = assembly
        self.function = function
    def __str__(self) -> str:
        #add function name if function is not None
        function_string = f"  Function: {self.function}"+"\n" if self.function else ""
        assembly_string = str(self.assembly).replace('\n','\n    ')
        return f"Address: {hex(self.address)}:"+"\n"+f"{function_string}  Size: {self.size} bytes"+"\n"+f"  Number of Instructions: {self.instructions}"+"\n"+f"  Disassembly:"+"\n"+f"    {assembly_string}"


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
        
