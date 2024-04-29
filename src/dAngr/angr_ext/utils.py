import importlib
import inspect
import os
import angr

from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError



def set_memory(value_type,value,address,state): 
    if type(value_type) is angr.sim_type.SimTypeInt:
        # Convert string to integer, respecting potential hex format
        value = int(value, 0)
        # Account for endianness when storing integers
        if state.arch.memory_endness.replace('Iend_', '').lower()=='le':
            endianness = 'little'
        else:
            endianness = 'big'
        byte_value = value.to_bytes(state.arch.bits // 8, byteorder=endianness)
    elif type(value_type) is angr.sim_type.SimTypePointer:
        # Encode string to bytes
        if isinstance(value, str):
            byte_value = value.encode()
        else:
            byte_value = value
        if not isinstance(byte_value, bytes):
            raise InvalidArgumentError("Value is not a byte array.")
    else:
        raise InvalidArgumentError(f"Unknown type '{value_type}'. Use 'int', 'str', or 'bytes'.")
    state.memory.store(address, byte_value)

def convert_string(sim_type, value):
    if isinstance(sim_type, angr.sim_type.SimTypeInt):
        return int(value,0)
    elif isinstance(sim_type, angr.sim_type.SimTypePointer) :
        return eval(value)
    elif isinstance(sim_type, angr.sim_type.SimTypeDouble()) or isinstance(sim_type, angr.sim_type.SimTypeFloat()):
        return float(value)
    else:
        raise InvalidArgumentError(f"arg_type {sim_type} not implemented")
    
def get_function_by_addr(proj,addr):
    return proj.kb.functions.ceiling_func(addr)
    # if proj.kb.functions.contains_addr(addr):
    #         return proj.kb.functions.get_by_addr(addr)
    # for func in proj.kb.functions.values():
    #     if func.addr <= addr < func.addr + func.size:
    #         return func
    # return None

def load_module_from_file(file_path):
    # Extract filename without extension
    module_name = os.path.splitext(os.path.basename(file_path))[0]

    # Create spec for the module
    spec = importlib.util.spec_from_file_location(module_name, file_path)

    # Load the module
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module

def hook_simprocedures(project, module):
    hooks = []
    for obj_name in dir(module):
        obj = getattr(module, obj_name)
        if inspect.isclass(obj) and issubclass(obj, angr.SimProcedure):
            hooks.append(obj_name)
            project.hook_symbol(obj_name, obj())
    return hooks

