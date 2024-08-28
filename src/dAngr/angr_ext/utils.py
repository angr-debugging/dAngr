import importlib
import importlib.util
import inspect
import os
import types
from typing import Any, Set, List, Tuple
from angr import Project, SimCC, SimProcedure, SimState, SimulationManager, types, knowledge_plugins



from dAngr.angr_ext.std_tracker import StdTracker
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError

def evaluate_symbolic_string(symbolic_str, solver, length):
    result = []
    for i in range(length):
        byte = symbolic_str.get_byte(i)
        result.append(solver.eval(byte, cast_to=int))
    return bytes(result)

def create_entry_state(project:Project, 
                       entry_point:int|Tuple[str,types.SimTypeFunction,SimCC,List[Any]]|None= None, 
                       default_state_options:Set[str]=set())-> Tuple[SimulationManager,SimState]:
        
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
        simgr = project.factory.simulation_manager(state)
        return simgr,state

def get_function_address(project, function_name):
    for symbol in project.loader.symbols: 
        if symbol.name == function_name:
            return symbol.rebased_addr
    return None

# def value_to_simtype(value):
#     if isinstance(value, int):
        
#         return angr.types.SimTypeInt()
#     elif isinstance(value, float):
#         return angr.types.SimTypeDouble()
#     elif isinstance(value, str):
#         return angr.types.SimTypePointer()
#     else:
#         raise InvalidArgumentError(f"arg_type {type(value)} not implemented")
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

def get_bb_end_address(state)->int:
    bb = state.project.factory.block(state.addr)
    if not bb.instruction_addrs:
        return state.addr
    return bb.instruction_addrs[-1]

def load_module_from_file(file_path):
    # Extract filename without extension
    module_name = os.path.splitext(os.path.basename(file_path))[0]

    # Create spec for the module
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None:
        raise FileNotFoundError(f"File '{file_path}' not found.")
    if spec.loader is None:
        raise ImportError(f"Failed to load '{file_path}'.")
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

