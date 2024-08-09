from enum import Enum, auto
import importlib
import os
import inspect
import sys
from typing import get_args

from claripy import List
import re

class Type(Enum):
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