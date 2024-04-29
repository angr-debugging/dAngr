import json

class Response:
    def __init__(self,data,format=None):
        self.data = data
        self.format = format
    def __str__(self):
        d = self.data
        if isinstance(self.data, list):
            d = {"self":"\n ".join([str(s) for s in self.data])}            
        if self.format:
            if isinstance(d, dict):
                return self.format.format(**d)
            else:
                return self.format.format(self=d)
        return  str(d)
    
class Breakpoint:
    def __init__(self, address=None, source=None, line_nr=None, enabled=True):
        self.address = address  # The memory address of the breakpoint
        self.source = source    # The source file in which the breakpoint is set
        self.line_nr = line_nr  # The line number of the breakpoint in the source file
        self.enabled = enabled  # Whether the breakpoint is currently active

    def __str__(self):
        status = "Enabled" if self.enabled else "Disabled"
        if self.line_nr is None:
            return f"Breakpoint at {hex(self.address)} - {status}"
        else:
            return f"Breakpoint at {hex(self.address)} in {self.source} line  {self.line_nr} - {status}"

class Register:
    def __init__(self,name,size,value):
        self.name = name
        self.size = size
        self.value = value
    def __str__(self) -> str:
        v = self.value if not self.value.concrete else self.value.concrete_value
        return f"Register {self.name} ({self.size} bits): {v}"

class Memory:
    def __init__(self,address,value,value_type):
        self.address = address
        self.value_type = value_type
        self.value = value
    def __str__(self) -> str:
        return f"Memory at {hex(self.address)}: {self.value} ({self.value_type})"
    
class State:
    def __init__(self,index,address,ended=False):
        self.index:int = index
        self.address:int = address
    def __str__(self) -> str:
        return f"State {self.index} at {hex(self.address)}"
    
class BasicBlock:
    def __init__(self,address, size, instructions, assembly):
        self.address = address
        self.size = size
        self.instructions = instructions
        self.assembly = assembly
    def __str__(self) -> str:
        return f"Address: {hex(self.address)}:\nSize: {self.size} bytes\nNumber of Instructions: {self.instructions}\nDisassembly:\n{self.assembly}"
    
class StateExecution:
    def __init__(self,index,output):
        self.index = index
        self.output = output
    def __str__(self) -> str:
        return f"State {self.index} at {self.output}"

class SymbolicVariable:
    def __init__(self,name,value):
        self.name = name
        self.value = value
    def __str__(self) -> str:
        return f"Symvar: {self.name}: {self.value}"

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