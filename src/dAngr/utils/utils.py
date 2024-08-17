from enum import Enum, auto
import importlib
import os
import inspect
import sys
from typing import Union, get_args

from claripy import List
import re


DEBUG:bool = os.getenv("BUILD_TYPE","Release").lower() == "debug"

class DataType(Enum):
    int = auto()
    str = auto()
    bytes = auto()
    bool = auto()
    double = auto()
    hex = auto()

class StreamType(Enum):
    stdin = 0
    stdout = 1
    stderr = 2

class ArgumentSpec():
    def __init__(self, name:str, dtype:type, description:str, default = None):
        self.name = name
        self.type = dtype
        self.description = description
        self.default = default

def parse_docstring(docstring:str):
    # parse the description, args, short name, and extra info, return value from the docstring, Don't care about the errors raised
    description = ""
    args = []
    example = ""
    short_name = ""
    return_value = ""

    state = 0
    if docstring:
        lines = docstring.split("\n")
        description = lines[0]
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Args:"):
                state = 1
                if line.endswith(":"):
                    continue
            elif line.startswith("Short name:"):
                if line.endswith(":"):
                    continue
                state = 2
            elif line.startswith("Returns:"):
                state = 3
                if line.endswith(":"):
                    continue
            elif line.startswith("Raises:"):
                state = 4
                if line.endswith(":"):
                    continue
            elif line.startswith("Example:"):
                state = 5
                if line.endswith(":"):
                    continue
            if state == 0:
                description += line
            elif state == 1:
                args.append(line)
            elif state == 2:
                short_name = line.split(":")[1].strip()
            elif state == 3:
                return_value = line
            elif state == 4:
                # parse the raises
                pass
            if state == 5:
                example += line
    args = parse_args(args)

    return {"description":description, "args":args, "short_name":short_name, "extra_info":example, "return_value":return_value}

def convert_args(args, signature):
    # convert the args to the correct type
    pargs = []
    for name in args:
        a = signature.parameters.get(name)
        if not a:
            raise ValueError(f"Function {signature} does not have a parameter named {name}")
        arg = args[name]
        tp = arg["type"]
        if a.annotation == inspect._empty:
            raise ValueError(f"Function {signature} parameter {name} does not have a type annotation")
        if tp != a.annotation:
            raise ValueError(f"Function {signature} parameter {name} has type {a.annotation} but expected {tp}")
        description = arg["description"]
        default = a.default if a.default != inspect._empty else None
        pargs.append(ArgumentSpec(name,tp,description, default))  # type: ignore
    return pargs

def str_to_type(dtype:str):
    #convert string dtype to typings type
    tp = None
    if dtype == "int":
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
    else:
        try:
            tp = eval(dtype)
        except:
            raise ValueError(f"Invalid data type {dtype}")
    return tp

def parse_args(args):
    # parse the args
    parsed_args = {}
    for arg in args:
        arg = arg.strip()
        if arg:
            if ":" in arg:
                name_type, description = arg.split(":")
                name, dtype = name_type.strip().split(' ')
                dtype = dtype.strip('(').strip(')').strip()
                #convert string dtype to typings type
                tp = str_to_type(dtype)
                parsed_args[name] = {"type":tp, "description":description.strip()}
            else:
                # TODO add multiline support
                raise ValueError(f"Invalid argument specification: {arg}")  
    return parsed_args

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
            if tokens[i].startswith(('\'','"')):
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