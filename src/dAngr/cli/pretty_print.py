import angr
import claripy

from dAngr.angr_ext.models import BasicBlock
from dAngr.cli.models import Register


class PrettyPrint():
    def print(self, obj, indent):
        return " "* indent + str(obj)


class StatePrinter(PrettyPrint):
    def print(self, obj, indent):
        state:angr.SimState = obj
        return " "*indent + f"State: {hex(state.addr)}"
    
    
class ListPrinter(PrettyPrint):
    def print(self, obj, indent):
        if len(obj) == 0:
            return "[]"
        #if the elements are objects, convert them to strings with a newline in between
        if all([isinstance(e, object) for e in obj]):
            return "\n".join([pretty_print(e, indent) for e in obj])
        return f"[{', '.join([pretty_print(e, indent) for e in obj])}]"
class DictionaryPrinter(PrettyPrint):
    def print(self, obj, indent):
        if len(obj) == 0:
            return "{}"
        if all([isinstance(e, object) for e in obj]):
            #if the values are objects, print each entry as a name colon string rep of the value with a newline in between. End with a curly brace, each entry on a new line
            return "{" + "\n".join([f"{k}: {pretty_print(v, indent)}" for k,v in obj.items()]) + "}"
        #if the values are bae types, print the dictionary with curly braces
        return "{" + ", ".join([f"{k}: {v}" for k,v in obj.items()]) + "}"
class BasicBlockPrinter(PrettyPrint):
    def print(self, obj, indent):
        bb:BasicBlock = obj
        #print address, size, number of instructions and disassembly
        indentation = " "*indent
        return f"{indentation}Address: {hex(bb.address)}:\n{indentation}Size: {bb.size} bytes\n{indentation}Number of Instructions: {bb.instructions}\n{indentation}Disassembly:\n{pretty_print(bb.assembly, indent+2)}"

class RegisterPrinter(PrettyPrint):
    def print(self, obj, indent):
        reg:Register = obj
        v = reg.value if not reg.value.concrete else hex(reg.value.concrete_value)
        return f"{reg.name} (offset: {hex(reg.offset)}, size: {reg.size} bytes): {pretty_print(v)})"

class BVPrettyPrint(PrettyPrint):
    def print(self, obj, indent):
        bv:claripy.ast.BV = obj
        if bv.concrete:
            return f"{hex(bv.concrete_value)}"
        else:
            return f"BV with size:{bv.size()}"
list_printers = {
    angr.SimState:StatePrinter(), 
                 list:ListPrinter(), 
                 dict:DictionaryPrinter(), 
                 BasicBlock:BasicBlockPrinter(),
                Register:RegisterPrinter(),
                claripy.ast.BV:BVPrettyPrint()
                 }

def pretty_print(obj, indent=0):
    if obj is None:
        return "None"
    #if data is a list:
    #   if th elements are objects, convert them to strings with a newline in between
    #   if the elements are base types (integers, strings, bools, ...) convert them to a string, print the list with square brackets
    #if data is a dictionary:
    #   if the values are bae types, print the dictionary with curly braces
    #   if the values are objects, print each entry as a name colon string rep of the value with a newline in between. End with a curly brace, each entry on a new line
    #if data is an object, print the object, unless a template is provided
    return list_printers.get(type(obj), PrettyPrint()).print(obj, indent+2)    
