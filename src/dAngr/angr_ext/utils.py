import importlib
import importlib.util
import inspect
import os
import types
from typing import Any, Optional, Set, List, Tuple
from angr import Project, SimCC, SimProcedure, SimState, SimulationManager, types, knowledge_plugins
from dataclasses import dataclass

from enum import Enum, auto
import networkx as nx
import math

from dAngr.angr_ext.std_tracker import StdTracker
from dAngr.exceptions import DebuggerCommandError, InvalidArgumentError, FileNotFoundError


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

def is_plt_stub(project, addr):
        obj = project.loader.find_object_containing(addr)
        return obj is project.loader.main_object and obj.sections_map['.plt'].contains_addr(addr)



def convert_string(sim_type, value):
    if isinstance(sim_type, types.SimTypeInt):
        return int(value,0)
    elif isinstance(sim_type, types.SimTypePointer) :
        return eval(value)
    elif isinstance(sim_type, types.SimTypeDouble) or isinstance(sim_type, types.SimTypeFloat):
        return float(value)
    else:
        raise InvalidArgumentError(f"arg_type {sim_type} not implemented")

def _addr_in_func(f, addr: int) -> bool:
    # True if addr falls inside any of the function's basic blocks
    for b in f.blocks:
        size = b.size or 0
        if size and b.addr <= addr < b.addr + size:
            return True
    return False

def get_function_by_addr(proj:Project,addr) -> knowledge_plugins.functions.function.Function | None:
    f = proj.kb.functions.floor_func(addr)
    if (f is not None) and _addr_in_func(f, addr):
        return f
    


def get_function_by_name(proj:Project,name) -> knowledge_plugins.functions.function.Function | None:
    function_list = list(proj.kb.functions.get_by_name(name=name))
    if not function_list:
        return None
    
    return function_list[0]

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


@dataclass
class TSConfig:
    target_address: int | None = None

class SearchTechnique(Enum):
    DFS = auto()
    BFS = auto()
    TS = TSConfig()

    def set_target_address(self, address: Optional[int]) -> None:
        if self is not SearchTechnique.TS:
            raise ValueError("target_address is only valid for SearchTechnique.TS")
        self.value.target_address = address

    def get_target_address(self) -> Optional[int]:
        if self is not SearchTechnique.TS:
            return None
        return self.value.target_address
    
    # Initialise any parameters needed for the search technique
    def initialise(self, **kwargs) -> bool:
        if self == SearchTechnique.TS:
            target_address = kwargs.get('target_address', None)
            if(target_address is None):
                raise ValueError("target_address must be provided for TS search technique")

            self.set_target_address(target_address)
        return True

    def selector_func(self, run_ctx):
        if self in (SearchTechnique.DFS, SearchTechnique.BFS, SearchTechnique.TS):
            return lambda state: state == run_ctx.simgr.one_active
        raise ValueError(self)

    def after_step(self, run_ctx, simgr: SimulationManager, stepped_state):
        if self == SearchTechnique.DFS:
            return  # keep going deep
        
        if self == SearchTechnique.BFS:
            # rotate the just-stepped state to the back if still active
            if stepped_state in simgr.active and simgr.active and simgr.active[0] is stepped_state:
                simgr.active.pop(0)
                simgr.active.append(stepped_state)
            return

        if self == SearchTechnique.TS:
            target = self.get_target_address()
            if target is None:
                return

            # Build CFG once
            if not hasattr(self, "_ts_cfg"):
                self._ts_cfg = run_ctx.project.analyses.CFGFast()
            cfg = self._ts_cfg

            g = cfg.model.graph

            dst = cfg.model.get_any_node(int(target), anyaddr=True)
            if dst is None:
                return

            rev = g.reverse(copy=False)
            dist_to_target = dict(nx.single_source_shortest_path_length(rev, dst))

            def distance_to_target(state):
                try:
                    addr = state.addr
                    if not isinstance(addr, int):
                        addr = state.solver.eval(addr)
                except Exception as e:
                    return math.inf

                src = cfg.model.get_any_node(addr, anyaddr=True)
                if src is None:
                    return math.inf

                d = dist_to_target.get(src, math.inf)
                return d

            # Debug before sorting: compute distances once so we can log summary
            distances = []
            inf_count = 0
            for st in simgr.active:
                d = distance_to_target(st)
                distances.append((d, st))
                if d == math.inf:
                    inf_count += 1

            # Log the 10 closest states (by distance)
            for d, st in sorted(distances, key=lambda x: x[0])[:10]:
                try:
                    a = st.addr if isinstance(st.addr, int) else st.solver.eval(st.addr)
                except Exception:
                    a = None

            # Now sort using the precomputed distances (avoids recomputing inside sort)
            dist_map = {id(st): d for d, st in distances}
            simgr.active.sort(key=lambda st: dist_map.get(id(st), math.inf))

            return
        raise ValueError(self)