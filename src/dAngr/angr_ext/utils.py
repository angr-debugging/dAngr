from enum import Enum, auto
import elftools
import elftools.dwarf
import elftools.dwarf.die
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser
import importlib
import importlib.util
import os
import types
from typing import Any, Literal, Set, List, Tuple, cast
import inspect
from angr import Project, SimCC, SimProcedure, SimState, SimulationManager, types, knowledge_plugins
import archinfo
import claripy



from dAngr.angr_ext.std_tracker import StdTracker
from dAngr.exceptions import DebuggerCommandError, InvalidArgumentError, FileNotFoundError



#create a undefined type
undefined = type("Undefined", (), {})


class Operator(Enum):
    POW = auto()
    MOD = auto()
    MUL = auto()
    DIV = auto()
    FLOORDIV = auto()  
    ADD = auto()
    SUB = auto()
    LSHIFT = auto() 
    RSHIFT = auto()  
    XOR = auto()     
    BITWISE_AND = auto()  
    EQ = auto()
    NEQ = auto()
    GT = auto()
    LT = auto()
    LE = auto()
    GE = auto()
    BITWISE_OR = auto()  
    AND = auto()  
    OR = auto()

    def __repr__(self):
        switch = {
            Operator.POW: "**",
            Operator.MOD: "%",
            Operator.MUL: "*",
            Operator.DIV: "/",
            Operator.FLOORDIV: "//",
            Operator.ADD: "+",
            Operator.SUB: "-",
            Operator.LSHIFT: "<<",
            Operator.RSHIFT: ">>",
            Operator.XOR: "^",
            Operator.BITWISE_AND: "&",
            Operator.BITWISE_OR: "|",
            Operator.EQ: "==",
            Operator.NEQ: "!=",
            Operator.GT: ">",
            Operator.LT: "<",
            Operator.LE: "<=",
            Operator.GE: ">=",
            Operator.AND: "and",
            Operator.OR: "or"
        }
        return switch[self]
    def __str__(self) -> str:
        return self.__repr__()
    @property
    def precedence(self):
        return Operator.operator_precedence(self)
    
    @staticmethod
    def operator_precedence(op):
        switch = {
            Operator.POW : 7,
            Operator.MOD : 6,
            Operator.MUL : 6,
            Operator.DIV : 6,
            Operator.FLOORDIV : 6,  
            Operator.ADD : 5,
            Operator.SUB : 5,
            Operator.LSHIFT : 4,
            Operator.RSHIFT : 4,  
            Operator.XOR : 4, 
            Operator.BITWISE_AND : 3,
            Operator.EQ : 3,
            Operator.NEQ : 3,
            Operator.GT : 3,
            Operator.LT : 3,
            Operator.LE : 3,
            Operator.GE : 3,
            Operator.BITWISE_OR : 2,
            Operator.AND : 2,
            Operator.OR : 1, 
        }
        return switch.get(op, 0)
    # Method resolution based on Python's magic methods
    @staticmethod
    def convert_to_magic_method(op):
        switch = {
            Operator.POW: "__pow__",
            Operator.MOD: "__mod__",
            Operator.MUL: "__mul__",
            Operator.DIV: "__truediv__",  
            Operator.FLOORDIV: "__floordiv__",  
            Operator.ADD: "__add__",
            Operator.SUB: "__sub__",
            Operator.LSHIFT: "__lshift__",  
            Operator.RSHIFT: "__rshift__",  
            Operator.XOR: "__xor__",       
            Operator.BITWISE_AND: "__and__",  
            Operator.BITWISE_OR: "__or__",   
            Operator.EQ: "__eq__",
            Operator.NEQ: "__ne__",  
            Operator.GT: "__gt__",
            Operator.LT: "__lt__",
            Operator.LE: "__le__",
            Operator.GE: "__ge__"
        }
        return switch.get(op, None)
    

class Endness(Enum):
    LE = auto()
    BE = auto()
    DEFAULT = auto()
    MEMORY = auto()
    REGISTER = auto()
    def to_arch_endness(self, project):
        switch = {
            Endness.LE: archinfo.Endness.LE,
            Endness.BE: archinfo.Endness.BE,
            Endness.MEMORY: project.arch.memory_endness,
            Endness.REGISTER: project.arch.register_endness,
            Endness.DEFAULT: archinfo.Endness.BE
        }
        return switch.get(self, archinfo.Endness.BE)
    
    def to_byteorder(self, arch:archinfo.Arch)->Literal["little", "big"]:
        little = 'little'
        big = 'big'
        switch = {
            Endness.LE: little,
            Endness.BE: big,
            Endness.MEMORY: little if arch.memory_endness == archinfo.Endness.LE else big,
            Endness.REGISTER: little if arch.register_endness == archinfo.Endness.LE else big,
            Endness.DEFAULT: big
        }
        en = switch.get(self, big)
        return cast(Literal["little", "big"], en)

class SolverType(Enum):
    UpTo = auto()
    AtLeast = auto()
    Exact = auto()

class DataType(Enum):
    int = auto()
    str = auto()
    bytes = auto()
    bool = auto()
    hex = auto()
    address = auto()
    none = auto()

    def to_type(self)->type:
        switch = {
            DataType.int: int,
            DataType.str: str,
            DataType.bytes: bytes,
            DataType.bool: bool,
            DataType.hex: str,
            DataType.address: int,
            DataType.none: type(None)
        }
        return switch.get(self, type(None))

    def convert(self, value, arch:archinfo.Arch, **kwargs):
        if not type(value) in [int, str, bytes, bool]:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', 'bytes', or 'bool'.")
        switch = {
            DataType.int: DataType._to_int,
            DataType.str: DataType._to_str,
            DataType.bytes: DataType._to_bytes,
            DataType.bool: DataType._to_bool,
            DataType.hex: DataType._to_hex,
            DataType.address: DataType._to_address
        }
        return switch.get(self, None)(value, arch, **kwargs)

    @staticmethod
    def _to_int(value, arch:archinfo.Arch, endness:Endness=Endness.DEFAULT):
        if not type(value) in [int, str, bytes, bool]:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', 'bytes', or 'bool'.")
        if type(value) == int:
            return value
        elif type(value) == str:
            if value.startswith('0x'):
                return int(value, 16)
            return int(value, 0)
        elif type(value) == bytes:
            return int.from_bytes(value, byteorder=endness.to_byteorder(arch))
        elif type(value) == bool:
            return int(value)
        raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")
    
    @staticmethod
    def _to_address(value, arch:archinfo.Arch, endness:Endness=Endness.DEFAULT):
        if not type(value) in [int, str, bytes, bool]:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', 'bytes', or 'bool'.")
        if type(value) == int:
            v = value
        elif type(value) == str:
            v = int(value, 0)
        elif type(value) == bytes:
            v = int.from_bytes(value, byteorder=endness.to_byteorder(arch))
        elif type(value) == bool:
            v = int(value)
        else:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")
        return hex(v)
    
    @staticmethod
    def _to_hex( value, arch:archinfo.Arch, endness:Endness=Endness.DEFAULT):
        if not type(value) in [int, str, bytes, bool]:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', 'bytes', or 'bool'.")
        if type(value) == int:
            return hex(value)
        elif type(value) == str:
            return DataType._to_bytes(value, arch, endness).hex(":")
        elif type(value) == bytes:
            return value.hex(":")
        elif type(value) == bool:
            return hex(int(value))
        raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")

    @staticmethod
    def _to_str(value, arch:archinfo.Arch):
        if not type(value) in [int, str, bytes, bool]:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', 'bytes', or 'bool'.")
        if type(value) == int:
            return str(value)
        elif type(value) == bytes:
            return value.decode('utf-8', errors='replace')
        elif type(value) == str:
            return value
        elif type(value) == bool:
            return str(value)
        raise DebuggerCommandError(f"Type not supported. Use 'int' or 'bytes'.")

    @staticmethod
    def _to_bool(value, arch:archinfo.Arch, endness:Endness=Endness.DEFAULT):
        if not type(value) in [int, str, bytes, bool]:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', 'bytes', or 'bool'.")
        if type(value) == int:
            return bool(value)
        elif type(value) == str:
            return value.lower() in ['true', '1']
        elif type(value) == bytes:
            return bool(int.from_bytes(value, byteorder=endness.to_byteorder(arch)))
        elif type(value) == bool:
            return value
        raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")

    @staticmethod
    def _to_bytes(value, arch:archinfo.Arch, endness:Endness=Endness.DEFAULT):
        if not type(value) in [int, str, bytes, bool]:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', 'bytes', or 'bool'.")
        if type(value) == int:
            # Account for endianness when storing integers
            byte_value = value.to_bytes(arch.bytes, byteorder=endness.to_byteorder(arch))
        elif type(value) == str:
            byte_value = value.encode('utf-8')
        elif type(value) == bytes:
            byte_value = value
        elif type(value) == bool:
            byte_value = int(value).to_bytes(1, byteorder=endness.to_byteorder(arch))
        else:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")
        return byte_value

class StreamType(Enum):
    stdin = 0
    stdout = 1
    stderr = 2
    
class ObjectStore(Enum):
    mem = auto()
    sym = auto()
    reg = auto()
    io = auto()



Constraint = claripy.ast.Bool
SymBitVector = claripy.ast.BV
class Variable:
    @property
    def value(self):
        pass
    @value.setter
    def value(self, value):
        pass

AngrValueType = SymBitVector | int | str | bytes | bool
AngrObjectType = AngrValueType | Variable
AngrType = AngrValueType | AngrObjectType
AngrCompoundType = dict[str, AngrValueType] | list[AngrValueType]
AngrExtendedType = Variable | AngrCompoundType

class Variable:
    def __init__(self, name:str, value:AngrExtendedType):
        self.name = name
        assert not isinstance(value, Variable)
        self._value = value

    @property
    def value(self) ->AngrExtendedType:   
        return self._value
    @value.setter
    def value(self, value:AngrExtendedType):
        assert isinstance(value, AngrValueType) or isinstance(value, list) or isinstance(value, dict), "Invalid Variable Type"
        self._value = value
    
    def __repr__(self):
        return f"{self.name}={self._value}"

def evaluate_symbolic_string(symbolic_str, solver, length):
    result = []
    for i in range(length):
        byte = symbolic_str.get_byte(i)
        result.append(solver.eval(byte, cast_to=int))
    return bytes(result)

def create_entry_state(project:Project, 
                       entry_point:int|Tuple[str,types.SimTypeFunction,SimCC,List[Any]]|None= None, 
                       default_state_options:Set[str]=set(), state = None,
                       veritesting:bool=False)-> Tuple[SimulationManager,SimState]:
        if not state:
            if entry_point is None:
                state = project.factory.entry_state(add_options=default_state_options)
            elif isinstance(entry_point,int):
                state = project.factory.blank_state(addr=entry_point, add_options=default_state_options)
            else:
                name,prototype,cc,arguments = entry_point
                addr = get_function_address(project,name)
                state = project.factory.call_state( 
                    addr,
                    *arguments,
                    prototype=prototype,
                    cc=cc,
                    base_state=None,
                    ret_addr=project.simos.return_deadend, 
                    toc=None,
                    add_options= default_state_options,
                    remove_options=None,
                )
        state.register_plugin('stdout_tracker', StdTracker())
        simgr = project.factory.simulation_manager(state, veritesting=veritesting)
        return simgr,state

def get_function_address(project, function_name):
    for symbol in project.loader.symbols: 
        if symbol.name == function_name:
            return symbol.rebased_addr
    if f := project.kb.functions.function(name=function_name):
        return f.addr
    return None


def convert_string(sim_type, value):
    if isinstance(sim_type, types.SimTypeInt):
        return int(value,0)
    elif isinstance(sim_type, types.SimTypePointer) :
        return eval(value)
    elif isinstance(sim_type, types.SimTypeDouble) or isinstance(sim_type, types.SimTypeFloat):
        return float(value)
    else:
        raise InvalidArgumentError(f"arg_type {sim_type} not implemented")
    
def get_function_by_addr(proj,addr) -> knowledge_plugins.functions.function.Function | None:
    return proj.kb.functions.ceiling_func(addr)

def get_function_by_name(proj,name) -> knowledge_plugins.functions.function.Function | None:
    function_list = list(proj.kb.functions.get_by_name(name=name))
    if not function_list:
        return None
    
    return function_list[0]

def get_bb_end_address(state)->int:
    bb = state.project.factory.block(state.addr)
    if not bb.instruction_addrs:
        return state.addr
    return bb.instruction_addrs[-1]

class FunctionInfo:
    def __init__(self, name, addr, args, vars):
        self.name = name
        self.addr = addr
        self.args = args
        self.vars = vars

class DebugInfo:
    def __init__(self, file, base_addr):
        self.functions = {}
        self.globals = {}
        self.types = {}
        self.file = file
        self.parse_elf_debug_info(file, base_addr)

    def resolve_type(self, dwarfinfo, DIE):
        """ Recursively resolve a type DIE to find its name. """
        if DIE is None:
            return "<unknown type>"

        if DIE.tag == "DW_TAG_array_type":
            base_type_DIE = self.get_attr_value(DIE, "DW_AT_type")
            base_type_name = self.resolve_type(dwarfinfo, base_type_DIE) if isinstance(base_type_DIE, elftools.dwarf.die.DIE) else "<unknown base type>"

            # Extract dimensions
            dimensions = []
            for child in DIE.iter_children():
                if child.tag == "DW_TAG_subrange_type":
                    count_attr = child.attributes.get("DW_AT_count") or child.attributes.get("DW_AT_upper_bound")
                    if count_attr:
                        dimensions.append(count_attr.value + 1)  # DW_AT_upper_bound is 0-based

            dim_str = "".join(f"[{d}]" for d in dimensions) if dimensions else "[]"
            return f"{base_type_name}{dim_str}"
        if DIE.tag == "DW_TAG_pointer_type":
            type_ref = DIE.attributes["DW_AT_type"].value
            base_type_DIE = dwarfinfo.get_DIE_from_refaddr(type_ref)
            return f"{self.resolve_type(dwarfinfo, base_type_DIE)} *"
        if "DW_AT_name" in DIE.attributes:
            return DIE.attributes["DW_AT_name"].value.decode("utf-8")

        if "DW_AT_type" in DIE.attributes:
            type_ref = DIE.attributes["DW_AT_type"].value
            DIE = DIE.cu.get_DIE_from_refaddr(type_ref)
            return self.resolve_type(dwarfinfo, DIE)

        return "<unknown type>"
    # def get_attr_value(self, DIE, attr_name, dwarfinfo):
    #     """ Retrieve an attribute's value, resolving references if needed. """
    #     if attr_name not in DIE.attributes:
    #         raise KeyError(f"Attribute '{attr_name}' not found in DIE.")
    #     attr = DIE.attributes[attr_name]
    #     # Direct value
    #     if attr.form.startswith("DW_FORM_strp") or attr.form.startswith("DW_FORM_string"):
    #         return attr.value.decode("utf-8")
    #     elif attr.form.startswith("DW_FORM_ref"):  # It's a reference
    #         ref_DIE = dwarfinfo.get_DIE_from_refaddr(attr.value)
    #         if ref_DIE and "DW_AT_name" in ref_DIE.attributes:
    #             return self.get_attr_value(ref_DIE, "DW_AT_name", dwarfinfo)
    #         if ref_DIE and "DW_AT_type" in ref_DIE.attributes:
    #             return self.resolve_type(dwarfinfo, ref_DIE)
    #         return attr.value
    #     else:
    #         return attr.value
    def decode_exprloc(self, attr, dwarfinfo):
        """ Decodes a DW_FORM_exprloc and prints its operations """
        if attr.form == "DW_FORM_exprloc":
            expr_parser = DWARFExprParser(dwarfinfo.structs)
            ops = expr_parser.parse_expr(attr.value)
            return ops
        return None
    def get_attr_value(self,DIE, attr_name):
        """ Retrieve an attribute's value, resolving references if needed. """
        if attr_name not in DIE.attributes:
            return None

        attr = DIE.attributes[attr_name]
        
        # Direct string values
        if attr.form.startswith("DW_FORM_strp") or attr.form.startswith("DW_FORM_string"):
            return attr.value.decode("utf-8")
        
        # Reference type handling
        if attr.form.startswith("DW_FORM_ref"):
            return DIE.cu.get_DIE_from_refaddr(attr.value)
        
        if attr.form.startswith("DW_FORM_exprloc"):
            return self.decode_exprloc(attr, DIE.cu.dwarfinfo)

        return attr.value
    def get_variable(self, DIE, tp='DW_TAG_variable'):
        vars = []
        line_program = DIE.cu.dwarfinfo.line_program_for_CU(DIE.cu)
        if not line_program:
            return

        file_id = self.get_attr_value(DIE, "DW_AT_decl_file")
        if file_id:
            file = line_program['file_entry'][file_id - 1].name # type: ignore
        line = self.get_attr_value(DIE, "DW_AT_decl_line")
        column = self.get_attr_value(DIE, "DW_AT_decl_column")
        type_DIE = self.get_attr_value(DIE, "DW_AT_type")
        type_name = self.resolve_type(DIE.cu.dwarfinfo, type_DIE)
        # loc = self.get_attr_value(DIE, "DW_AT_location")
        var_name = self.get_attr_value(DIE, "DW_AT_name")
        return {"name":var_name, "file":file, "line":line, "column":column, "type":type_name}
    def get_variables(self, DIE):
        vars = []
        for child in DIE.iter_children():
            if child.tag == "DW_TAG_variable" and "DW_AT_name" in child.attributes:
                var = self.get_variable(child)
                if var:
                    vars.append(var)
            elif child.tag == "DW_TAG_lexical_block":
                vars.extend(self.get_variables(child))
        return vars
    
    def parse_elf_debug_info(self, file, base_addr):
        elf = ELFFile(open(file, 'rb'))
        #get all functions
        dwarfinfo = elf.get_dwarf_info()
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag == "DW_TAG_subprogram" and "DW_AT_name" in DIE.attributes:
                    func_name = self.get_attr_value(DIE, "DW_AT_name")
                    args = []
                    vars = []
                    line_program = dwarfinfo.line_program_for_CU(CU)
                    if not line_program:
                        continue
                    for child in DIE.iter_children():
                        if child.tag == "DW_TAG_formal_parameter" and "DW_AT_name" in child.attributes:
                            a = self.get_variable(child, child.tag)
                            args.append(a)
                    vars = self.get_variables(DIE)

                    self.functions[func_name] = FunctionInfo(func_name, DIE.attributes["DW_AT_low_pc"].value + base_addr, args, vars)
        #get all global variables
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag == "DW_TAG_variable" and "DW_AT_name" in DIE.attributes:
                    var_name = DIE.attributes["DW_AT_name"].value.decode("utf-8")
                    line_program = dwarfinfo.line_program_for_CU(CU)
                    if not line_program:
                        continue
                    file_id = DIE.attributes["DW_AT_decl_file"].value
                    file = line_program['file_entry'][file_id - 1].name
                    line = DIE.attributes["DW_AT_decl_line"].value
                    column = DIE.attributes["DW_AT_decl_column"].value
                    self.globals[var_name] = {"name":var_name, "file":file, "line":line, "column":column}


def load_module_from_file(file_path):
    # Extract filename without extension
    module_name = os.path.splitext(os.path.basename(file_path))[0]

    # Create spec for the module
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None:
        raise FileNotFoundError(f"File '{file_path}' not found.")
    if spec.loader is None:
        raise DebuggerCommandError(f"Failed to load '{file_path}'.")
    # Load the module
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module

def hook_simprocedures(project, module):
    hooks = []
    for obj_name in dir(module):
        obj = getattr(module, obj_name)
        if inspect.isclass(obj) and issubclass(obj, SimProcedure):
            hooks.append(obj_name)
            project.hook_symbol(obj_name, obj())
    return hooks

