from array import array
import codecs
from enum import Enum, auto
import importlib
import os
import inspect
from typing import Literal, cast, get_args

import archinfo
from claripy import List
import re

import claripy

from dAngr.exceptions import DebuggerCommandError, InvalidArgumentError, ValueError



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


def is_indexable(obj):
    return hasattr(obj, '__getitem__')

def is_iterable(obj):
    return hasattr(obj, '__iter__') or isinstance(obj, array)

def str_to_type(dtype:str):
    #convert string dtype to typings type
    tp = None
    if dtype == '':
        tp = None
    elif dtype == "int":
        tp = int
    elif dtype == "str":
        tp = str
    elif dtype == "bytes":
        tp = bytes
    elif dtype == "bool":
        tp = bool
    elif dtype == "double":
        tp = float
    elif dtype == "hex":
        tp = int
    elif dtype == "tuple":
        tp = tuple
    elif dtype == "list":
        tp = list
    elif dtype == "dict":
        tp = dict
    elif dtype == "set":
        tp = set
    elif dtype == 'array':
        tp = array
    else:
        try:
            from dAngr.cli.grammar.expressions import ReferenceObject,VariableRef, SymbolicValue, Register, Property, IndexedProperty
            import angr
            tp = eval(dtype)
        except:
            raise ValueError(f"Invalid data type {dtype}")
    return tp

def check_signature_matches(func, o, args, kwargs):
    # Get the function's signature
    signature = inspect.signature(func)
    
    try:
        # Bind the provided arguments to the function's signature
        bound_args = signature.bind(o, *args, **kwargs)
        bound_args.apply_defaults()  # Apply default values if any
    except TypeError as e:
        raise InvalidArgumentError(str(e))
    
    # Optionally: Perform type checking if the function has type hints

    for param_name, param_value in bound_args.arguments.items():
            p = signature.parameters.get(param_name)
            if p is None:
                raise InvalidArgumentError(f"Invalid argument '{param_name}', not found in signature")
            if p.name == "self":
                continue
            if p is None:
                raise InvalidArgumentError(f"Invalid argument '{param_name}', not found in signature")
            
            expected_type = p.annotation
            if inspect.isclass(expected_type) and  issubclass(expected_type ,Enum) and isinstance(param_value, str):
                #get the value of the expected enum type given the str
                param_value = expected_type[param_value]
            if p.kind == inspect.Parameter.VAR_POSITIONAL:
                    if not isinstance(param_value, tuple):
                        raise InvalidArgumentError(f"Argument '{param_name}' should be of type {expected_type.__name__ if isinstance(expected_type, type) else expected_type}, got {type(param_value).__name__}")
                    for t in param_value:
                        if expected_type != inspect._empty and  not isinstance(t, expected_type):
                            raise InvalidArgumentError(f"Argument '{param_name}' should be of type {expected_type.__name__ if isinstance(expected_type, type) else expected_type}, got {type(param_value).__name__}")
            elif p.kind == inspect.Parameter.VAR_KEYWORD:
                if not isinstance(param_value, dict):
                    raise InvalidArgumentError(f"Argument '{param_name}' should be of type {expected_type.__name__ if isinstance(expected_type, type) else expected_type}, got {type(param_value).__name__}")
                for k,v in param_value.items():
                    if expected_type != inspect._empty and  not isinstance(v, expected_type):
                        raise InvalidArgumentError(f"Argument '{param_name}' should be of type {expected_type.__name__ if isinstance(expected_type, type) else expected_type}, got {type(param_value).__name__}")
            elif expected_type != inspect._empty and not isinstance(param_value, expected_type):
                raise InvalidArgumentError(f"Argument '{param_name}' should be of type {expected_type.__name__ if isinstance(expected_type, type) else expected_type}, got {type(param_value).__name__}")
    
def parse_binary_string(binary_string_text):
    # Strip the `b'` prefix and trailing `'`
    if (binary_string_text.startswith("b'") and binary_string_text.endswith("'")) or (binary_string_text.startswith("b\"") and binary_string_text.endswith("\"")):
        binary_string_text = binary_string_text[2:-1]
    else:
        raise ValueError("Invalid binary string format")
    
    # Handle escape sequences (e.g., \0, \n, \\)
    parsed_string = codecs.decode(binary_string_text, 'unicode_escape')

    # Convert to bytes using 'latin1' to preserve the byte-to-byte mapping
    binary_data = parsed_string.encode('latin1')

    return binary_data

def convert_argument(arg_type: type, arg_value: str):
    try:
        # Handle Enums
        if isinstance(arg_type, type) and issubclass(arg_type, Enum):
            return arg_type[arg_value]

        # Handle Union types
        types = [arg_type]
        if members := get_union_members(arg_type):
            types = members
        if bool in types and arg_value.lower() in ['true', 'false']:
            return arg_value.lower() == 'true'
        if bytes in types:
            if (arg_value.startswith('b"') and arg_value.endswith('"')) or (arg_value.startswith("b'") and arg_value.endswith("'")):
                return bytes(arg_value[2:-1], 'utf-8')
        if int in types:
            if arg_value.startswith('0x'):
                if "^" in arg_value:
                    arg_value,_ = arg_value.split("^")
                    return int(arg_value, 16) ^ int(arg_value.split("^")[1], 16)
                return int(arg_value, 16)
            if arg_value.isnumeric():
                return int(arg_value)
            if arg_value.startswith('-') and arg_value[1:].isnumeric():
                return - int(arg_value[1:])
        if str in types:
            if arg_value.startswith(('\'', '"')) and arg_value.endswith(('\'', '"')):
                return arg_value[1:-1]
            return arg_value

        # If no type matched
        raise InvalidArgumentError(f"Failed to convert argument to any of the expected types {types} from '{arg_value}'")
    except ValueError:
        raise InvalidArgumentError(f"Failed to convert argument to type '{arg_type}' from '{arg_value}'")

def str_to_address(address:str):
    if address.startswith("0x"):
        return int(address, 16)
    return int(address)



def remove_xml_tags(text):
    # Use a regular expression to match and remove all tags
    clean_text = re.sub(r'<[^>]+>', '', text)
    return clean_text

def get_union_members(union_type):
    return get_args(union_type)

def parse_arguments(input:str, splitter):
    # Construct a regex pattern from the command's argument specifications
        # string arguments can be a signle word or words in double quotes
        # parse user_input:
        # 1. split by spaces
        # 2. if a word starts with double quote, join all words until the next double quote
        tokens:List[str] = [t.strip() for t in input.split(splitter)]
        if len(tokens) == 1 and not tokens[0]:
            tokens = []
        parsed_args = []
        i = 0
        while i < len(tokens):
            if tokens[i].startswith(('\'','"', 'b"','b\'')):
                t = tokens[i][0]
                j = i
                while j<len(tokens) and  not tokens[j].endswith(t):
                    j += 1
                parsed_args.append(splitter.join(tokens[i:j+1]))
                i = j
            else:
                parsed_args.append(tokens[i])
            i += 1
        return parsed_args

def get_python_classes_in_folder(folder_path):
    python_classes = []

    # Traverse the directory structure recursively
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                classes = get_classes_from_file(file_path)
                python_classes.extend(classes)

    return python_classes

def get_classes_from_file(file_path):
    classes = []

    # Attempt to import the module dynamically
    module_name = os.path.splitext(os.path.basename(file_path))[0]
    spec = importlib.util.spec_from_file_location(module_name, file_path) # type: ignore
    if spec is not None:
        module = importlib.util.module_from_spec(spec) # type: ignore
        try:
            spec.loader.exec_module(module)

            # Iterate over the members of the module
            for name, obj in inspect.getmembers(module):
                # Check if the member is a class
                if inspect.isclass(obj):
                    classes.append(obj)
                
        except:
            pass
    return classes


def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\\x1B\x9B])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


