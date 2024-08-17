from abc import abstractmethod
import json

from angr import SimState


class Breakpoint:
    def __init__(self, address, source=None, line_nr=None, enabled=True):
        self.address = address  # The memory address of the breakpoint
        self.source = source    # The source file in which the breakpoint is set
        self.line_nr = line_nr  # The line number of the breakpoint in the source file
        self.enabled = enabled  # Whether the breakpoint is currently active

    def __str__(self):
        status = "" if self.enabled else " (disabled)"
        if self.line_nr is None:
            return f"Breakpoint at {hex(self.address)}{status}"
        else:
            return f"Breakpoint at {hex(self.address)} in {self.source} line  {self.line_nr}{status}"
        
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
