from array import array
import codecs
from enum import Enum, auto
import importlib
import os
import inspect
from typing import Literal, cast, get_args, List

import archinfo
import re

import claripy
import platform

from dAngr.exceptions import DebuggerCommandError, InvalidArgumentError, ValueError




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
            from dAngr.angr_ext.expressions import ReferenceObject,VariableRef, SymbolicValue, Register, Property, IndexedProperty
            import angr
            tp = eval(dtype)
        except:
            raise ValueError(f"Invalid data type {dtype}")
    return tp

def get_local_arch():
    # Detect platform architecture
    machine = platform.machine()
    arch_map = {
        'x86_64': archinfo.ArchAMD64,
        'i386': archinfo.ArchX86,
        'arm': archinfo.ArchARM,
        'aarch64': archinfo.ArchAArch64,
        'mips': archinfo.ArchMIPS32,
        'mips64': archinfo.ArchMIPS64,
    }
    if machine in arch_map:
        return arch_map[machine]()
    else:
        raise ValueError(f"Unsupported architecture: {machine}")

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

def readfile(file_path):
    with open(file_path, 'r') as file:
        return file.read()
