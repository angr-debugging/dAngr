import json
import inspect
from typing import List, Type, TypeVar
from pydantic import BaseModel, Extra, Field
from dAngr.dap import dap_models  # Your generated models module

# Generate the command-to-model mapping
COMMAND_TO_MODEL = {}

class LaunchRequestArguments(dap_models.LaunchRequestArguments):
    program:str = Field(
        ...,
        description='Path to the program to debug'
    )
    args:List[str] = Field(
        [],
        description='Arguments to pass to the program'
    )
    cwd :str = Field(
        ".",
        description='The working directory of the program being debugged'
    )
class LaunchRequest(dap_models.LaunchRequest):
    arguments:LaunchRequestArguments = Field(
        ...,
        description='Arguments for the launch request'
    )

def generate_command_to_model_mapping():
    for name, obj in inspect.getmembers(dap_models, inspect.isclass):
        if issubclass(obj, BaseModel) and hasattr(obj, '__fields__'):
            #replace dap_models LaunchRequest with the custom LaunchRequest
            if name == 'LaunchRequest':
                obj = LaunchRequest
            if 'command' in obj.__fields__ and not obj.model_fields['command'].annotation is str:

                l = obj.model_fields['command'].annotation.__members__.items() # type: ignore
                if len(l)==1:
                    command_default_value = list(obj.model_fields['command'].annotation.__members__.keys())[0] # type: ignore
                else:
                    continue
                if command_default_value:  # Ensure there's a default command value
                    if command_default_value[-1] == "_": 
                        command_default_value = command_default_value[:-1]
                    COMMAND_TO_MODEL[command_default_value] = obj

generate_command_to_model_mapping()

def parse_request(json_string: str):
    """
    Parse a DAP JSON string using the command-to-model mapping to find and instantiate the appropriate model.
    """
    data = json.loads(json_string)
    command = data.get('command')
    model_cls = COMMAND_TO_MODEL.get(command)
    if model_cls:
        return model_cls.parse_raw(json_string)
    else:
        raise ValueError(f"No model found for command: {command}")


def parse_dap_message(message):
    # Find the end of the header (marked by two consecutive CRLF sequences)
    header_end = message.find('\r\n\r\n')
    if header_end == -1:
        raise ValueError("Invalid DAP message: header not found")

    # Extract the header from the message
    header = message[:header_end]
    h = {s.split(':')[0].strip(): s.split(':')[1].strip() for s in header.split('\r\n') if s}

    # Check if the Content-Length field is present in the header
    if 'Content-Length' not in h:
        raise ValueError("Invalid DAP message: Content-Length not found in header")

    # Extract the content length from the header
    content_length = int(h['Content-Length'])

    # Extract the body from the message
    body_start = header_end + len(b'\r\n\r\n')
    body = message[body_start:]

    # Check if the body length matches the content length specified in the header
    if len(body) != content_length:
        raise ValueError("Invalid DAP message: body length does not match Content-Length")
    
    return header, body