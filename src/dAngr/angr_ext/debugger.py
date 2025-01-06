import os
import re
import subprocess
from typing import Any, Callable, Dict, List, Tuple
import angr
from angr import SimCC, SimProcedure, SimulationManager, types
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.functions.function import Function
import angr.storage
import claripy

from dAngr.angr_ext.models import BasicBlock, DebugSymbol
from dAngr.angr_ext.step_handler import StepHandler, StopReason
from dAngr.cli.grammar.execution_context import Variable
from dAngr.cli.grammar.expressions import Constraint
from dAngr.cli.state_visualizer import StateVisualizer
from dAngr.utils.utils import AngrValueType, AngrObjectType, AngrType, DataType, DataType, Endness, SolverType, StreamType, SymBitVector, get_local_arch, remove_ansi_escape_codes
from dAngr.utils import utils
from .std_tracker import StdTracker
from .utils import create_entry_state, get_function_address, hook_simprocedures, load_module_from_file, get_function_by_name, get_function_by_addr
from .connection import Connection
from angr.storage.memory_mixins.convenient_mappings_mixin import *

from dAngr.exceptions import DebuggerCommandError
from dAngr.utils.loggers import get_logger
log = get_logger(__name__)
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError




class Debugger:
    def __init__(self, conn:Connection) -> None:
        self.conn = conn

        self._binary_path:str|None = None
        self._project:angr.project.Project|None = None
        self._simgr:angr.sim_manager.SimulationManager|None = None
        self._current_state:angr.SimState|None = None
        self._default_state_options = set()

        self._pause:bool = False

        self._base_addr:int = 0x400000
        self.verbose_step:bool = True
        self._function_prototypes = {}
        self._current_function:str = ''
        self._cfg:CFGFast|None = None
        self.stop_reason = StopReason.NONE
        self._save_unconstrained = False
        self._entry_point:int|Tuple[str,types.SimTypeFunction,SimCC,List[Any]]|None = None
        self._symbols:Dict[str,SymBitVector] = {}

    @property
    def project(self)->angr.project.Project:
        self.throw_if_not_initialized()
        return self._project # type: ignore
    @property
    def entry_point(self):
        return self._entry_point
    
    @property
    def cfg(self):
        if self._cfg is None:
            self.conn.send_info("Constructing cfg, this may take a while...")
            self._cfg = self.project.analyses.CFGFast(normalize=True)
        return self._cfg

    @property
    def simgr(self)->SimulationManager:
        if self._simgr is None:
            self.throw_if_not_initialized()
            if self._current_state is None:
                log.debug("Creating default simulation manager.")
                self.set_entry_state()
            self._simgr = self.project.factory.simulation_manager(self.current_state, save_unconstrained=self._save_unconstrained)
        return self._simgr
    
    @property
    def initialized(self):
        return self._project is not None
    @property
    def active(self,all=False):
        if all:
            return self._simgr and self._simgr.active and not self._simgr.deadended
        else: # there may be inactive states
            return self._simgr and self._simgr.active
    @property
    def finished(self, all=False):
        if all:
            return self._simgr and self._simgr.deadended and not self._simgr.active
        else: # there may be active states
            return self._simgr and self._simgr.deadended
    

    def unconstrained_fill(self, symbolic:bool ):
        if not symbolic:
            self._default_state_options = set([angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS])            
        else:
            self._default_state_options = set([angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS])            

    @property
    def current_state(self):
        self.throw_if_not_initialized()
        if not self._current_state:
            if self.simgr.active:
                self._current_state = self.simgr.one_active          
            elif self.simgr.deadended:
                self._current_state = self.simgr.one_deadended
            else:
                raise DebuggerCommandError("No active or deadended states.")
        return self._current_state
    
    @current_state.setter
    def current_state(self, state:angr.SimState):
        self._set_current_state(state)

    def _set_current_state(self, state):
        if state:
            state.register_plugin('stdout_tracker', StdTracker())
        self._current_state = state
                
    def set_current_state(self, stateID:int, stash="active"):
        if stash not in self.simgr.stashes:
            raise DebuggerCommandError(f"Stash {stash} not found.")
        if stateID >= len(self.simgr.stashes[stash]):
            raise DebuggerCommandError(f"State with ID {stateID} not found in stash {stash}.")
        self._set_current_state(self.simgr.stashes[stash][stateID])

    def move_state_to_stash(self, stateID:int, from_stash:str, to_stash:str):
        if from_stash not in self.simgr.stashes:
            raise DebuggerCommandError(f"Stash {from_stash} not found.")
        if to_stash not in self.simgr.stashes:
            #create the stash
            self.simgr.stashes[to_stash] = []
        if stateID >= len(self.simgr.stashes[from_stash]):
            raise DebuggerCommandError(f"State with ID {stateID} not found in stash {from_stash}.")
        state = self.simgr.stashes[from_stash][stateID]
        self.simgr.move(from_stash, to_stash,lambda  s: s == state )
        return state
    
    def to_stash(self, stash:str):
        if not self.simgr.active:
            raise DebuggerCommandError("No active state to move.")
        self.simgr.move("active", stash, lambda s: s == self.current_state)

    def throw_if_not_initialized(self):
        if self._project is None:
            raise DebuggerCommandError("project not initialized.")
    def throw_if_not_active(self):
        if not self._current_state:
            raise DebuggerCommandError("no active states.")
    def get_source_info(self, addr):
        try:
            elf = self.project.loader.find_object_containing(addr) 
            src = max(elf.addr_to_line[addr]) # type: ignore
            return self.substitute_path_inverse(src[0]), src[1]
        except KeyError:
            return None,0
        
    def _find_elf_object_by_source(self, sourcefile, line_number):
        # Iterate through all ELF objects loaded by the project's loader
        for elf_obj in self.project.loader.all_elf_objects: 
            # Check if the ELF object has DWARF information
            if hasattr(elf_obj, 'addr_to_line'):
                # Attempt to reverse-map the source file and line number to an address
                for addr in elf_obj.addr_to_line:
                    # Use addr_to_line to get line information for each address
                    line_info = max(elf_obj.addr_to_line[addr])
                    # Check if the line information matches the source file and line number
                    if line_info[0] == sourcefile and line_info[1] == line_number:
                        # If a match is found, return the ELF object and the matching address
                        return elf_obj, addr
        # Return None if no matching ELF object or address is found
        return None
    def find_address(self, sourcefile, line_number)->int|None:
        n = self._find_elf_object_by_source(self.substitute_path(sourcefile), line_number)
        if n:
            return n[1]
        return None
    
    def set_call_state(self, func_addr:int, arguments):
        if self._simgr is not None:
            self.reset_state()
        # TODO: check add_options
        self._set_current_state( self.project.factory.call_state(func_addr,*arguments,
                    add_options = self._default_state_options, save_unconstrained=self._save_unconstrained))

    def set_entry_state(self,addr = None, *args, **kwargs):
        if self._simgr is not None:
            self.reset_state()
        if addr:
            kwargs['addr'] = addr
        if args:
            kwargs['args'] = args
        if kwargs.get('add_options') is None:
            kwargs['add_options'] = self._default_state_options
        self._set_current_state(self.project.factory.entry_state(
                     **kwargs))
    
    def set_full_state(self, *args, **kwargs):
        if self._simgr is not None:
            self.reset_state()
        if args:
            kwargs['args'] = args
        if kwargs.get('add_options') is None:
            kwargs['add_options'] = self._default_state_options
        self._set_current_state(self.project.factory.full_init_state(
                    **kwargs))

    def set_blank_state(self, *args, **kwargs):
        if self._simgr is not None:
            self.reset_state()
        if args:
            kwargs['args'] = args
        if kwargs.get('add_options') is None:
            kwargs['add_options'] = self._default_state_options
        log.debug(f"Creating blank state with kwargs: {kwargs}")
        state = self.project.factory.blank_state(**kwargs)
        self._set_current_state(state)
        
    @property
    def keep_unconstrained(self):
        return self._save_unconstrained
    
    @keep_unconstrained.setter  
    def keep_unconstrained(self, value:bool):
        self._save_unconstrained = value
        self._simgr = None

    def set_function_prototype(self, return_type:str, name:str, args:List[str]):  
        # Parse argument types
        sim_arg_types = [angr.types.parse_type(arg.strip()) for arg in args]
        sim_return_type = angr.types.parse_type(return_type)

        # Create function prototype
        self._function_prototypes[name] = {"prototype":angr.types.SimTypeFunction(sim_arg_types, sim_return_type)} # type: ignore
    def store_function(self, name, prototype, addr, cc):
        self._function_prototypes[name] = {"prototype":prototype, "addr":addr, "cc":cc}

     
    def get_stored_function(self, name:str):
        f = self._function_prototypes.get(name) if name in self._function_prototypes else None
        if not f:
            raise DebuggerCommandError(f"Function {name} not found.")
        return f
    
    def set_current_function(self, name:str):
        self._current_function = name
    
    def get_function_cc(self):
        cc = angr.default_cc(self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None)
        if cc is None:
            raise DebuggerCommandError("Failed to get calling convention.")
        return cc(self.project.arch)
    
    def get_function_info(self, func) -> Function |None:
       self.cfg
       if type(func) is int:
        return get_function_by_addr(self.project, func)
       else:
        return get_function_by_name(self.project, func)
    
    def get_function_prototype(self, prototype:str, arguments:List[str]):
        return angr.SimCC.guess_prototype(arguments, prototype).with_arch(self.project.arch)
    
    def get_function_address(self, name:str):
        return get_function_address(self.project, name)
    
    def get_function_callstate(self, function_name:str, prototype:types.SimTypeFunction, cc:SimCC,arguments:List[Any]):
        self._entry_point = (function_name,prototype,cc,arguments)
        if self._simgr is not None:
            self.reset_state()
        self._simgr,_ = create_entry_state(self.project,self._entry_point,self._default_state_options, self._current_state, self.veritesting)
        return self.simgr.one_active

    def get_variables(self, func_addr):
        names = list(self.project.kb.dvars._dvar_containers)
        pc = claripy.BVV(func_addr+self._base_addr,64) # self._simgr.active[0].ip
        vars = []
        for name in names:
            
            v = self.project.kb.dvars._dvar_containers[name].from_pc(pc)
            if v:
                vars.append(v)
        return vars


    def has_dwarf(self):
        try:
            return self.project.loader.main_object.has_dwarf_info
        except Exception as e:
            return False


    def substitute_path(self,path:str):
        path = os.path.abspath(os.path.normpath(path))
        if path.startswith(self.from_src_path):
            return self.to_src_path + path[len(self.from_src_path):]
        return path
        
    def substitute_path_inverse(self,path:str):
        path = os.path.abspath(os.path.normpath(path))
        if path.startswith(self.to_src_path):
            return self.from_src_path + path[len(self.to_src_path):]
        return path
    
    def init(self, binary_path:str, base_addr:int=0, from_src_path=None, to_src_path=None, veritesting:bool=False, **kwargs): #support passing custom angr arguments to project
        self.reset_state()
        self.veritesting = veritesting
        self._binary_path = binary_path
        self.from_src_path = os.path.abspath(os.path.expanduser(os.path.normpath(from_src_path))) if from_src_path else ''
        self.to_src_path = os.path.abspath(os.path.expanduser(os.path.normpath(to_src_path))) if to_src_path else ''
        if not os.path.exists(binary_path):
            raise InvalidArgumentError(f"File '{binary_path}' does not exist")
        
        main_opts = kwargs

        if base_addr:
            main_opts['base_addr'] = base_addr

        self._project = angr.Project(binary_path, load_options={'load_debug_info': True, 'auto_load_libs': False, 'main_opts':main_opts})
        if self.has_dwarf():
            self.project.kb.dvars.load_from_dwarf()
    
    def get_binary_info(self):
        # get general info such as path, name, arch, entry point, etc
        self.throw_if_not_initialized()
        if self._binary_path is None:
            raise DebuggerCommandError("Binary path not set.")
        
        return {
            "path":self._binary_path, 
            "arch":f" {self.project.arch.name}  ({str(self.project.arch.bits)} bits)", 
            "endian":self.project.arch.memory_endness.replace('Iend_', ''),
            "entry_point":hex(self.project.entry), 
            "base_addr": hex(self.project.loader.main_object.mapped_base)
        }
    
    def get_stdin_variables(self):
        return self.current_state.solver.get_variables('file', self.current_state.posix.stdin.ident)

    def get_binary_security_features(self):
        # get security features such as canary, nx, pie, etc
        self.throw_if_not_initialized()
        # run checksec as a process and parse the output
        features = {}
        try:
            checksec = subprocess.run(f"checksec --file={self._binary_path}", cwd=os.path.abspath(os.curdir), capture_output=True, text=True, shell=True)
            if checksec.returncode != 0:
                raise DebuggerCommandError(f"Failed to run checksec: {checksec.stdout}")
            output = checksec.stdout
            lines = output.split("\n")
            headers = re.split(r'\s{2,}|\t',lines[0])
            values = [x for x in (remove_ansi_escape_codes(r) for r in re.split(r'\s{2,}|\t',lines[1])) if x.strip()]
            for i in range(len(headers)):
                features[headers[i]] = values[i]

        except Exception as e:
            raise DebuggerCommandError(f"Failed to run checksec: {e}")
        return features
    
    def add_symbol(self, name:str, sym:SymBitVector):
        self._symbols[name] = sym

    def remove_symbol(self, name:str):
        if name in self._symbols:
            self._symbols.pop(name)
        else:
            raise DebuggerCommandError(f"Symbol {name} not found.")

    def get_symbol(self, name:str):
        if name in self._symbols:
            return self._symbols[name]
        else : raise DebuggerCommandError(f"Symbol {name} not found.")
    def to_symbol(self, name:str, lst:list):
        self.add_symbol(name, claripy.Concat(*lst))
        
    def find_symbol(self, name:str):
        if name in self._symbols:
            return self._symbols[name]
        return None
    
    def eval_symbol(self, sym:SymBitVector|Constraint, dtype:DataType, **kwargs):
        if isinstance(sym, SymBitVector):
            return self.current_state.solver.eval(sym, cast_to=dtype.to_type(), **kwargs)
        elif isinstance(sym, utils.Constraint):
            #drop endness from kwargs
            if 'endness' in kwargs:
                kwargs.pop('endness')
            return self.current_state.solver.eval(sym, cast_to=dtype.to_type(), **kwargs)
        else:
            raise DebuggerCommandError(f"Invalid symbol type {type(sym)}.")
        
    def eval_symbol_n(self, sym:SymBitVector|Constraint, n:int,solver_type:SolverType, dtype:DataType,  **kwargs):
        switch = {
            SolverType.UpTo: self.current_state.solver.eval_upto,
            SolverType.AtLeast: self.current_state.solver.eval_atleast,
            SolverType.Exact: self.current_state.solver.eval_exact
        }
        f = switch.get(solver_type)
        if not f:
            raise DebuggerCommandError(f"Invalid solver type {solver_type}.")
        if isinstance(sym, SymBitVector):
            return f(sym, n, cast_to=dtype.to_type(), **kwargs)
        elif isinstance(sym, utils.Constraint):
            #drop endness from kwargs
            if 'endness' in kwargs:
                kwargs.pop('endness')
            return f(sym, n, cast_to=dtype.to_type(), **kwargs)
        else:
            raise DebuggerCommandError(f"Invalid symbol type {type(sym)}.")

    def satisfiable(self, constraint=None):
        self.throw_if_not_active()
        return self.current_state.satisfiable(extra_constraints=[constraint])



    def set_symbol(self, name, value):
        self._symbols[name] = value
    def is_symbolic(self, value):
        self.throw_if_not_active()
        return self.current_state.solver.symbolic(value)

    def add_constraint(self, cs):
        self.throw_if_not_active()
        self.current_state.add_constraints(cs)
    def make_value(self, value:AngrObjectType)->AngrValueType:
        if isinstance(value, Variable):
            if not value.value:
                raise DebuggerCommandError("Variable has no value.")
            return value.value
        return value
    
    def add_to_stack(self, value:AngrObjectType):
        self.throw_if_not_active()
        v = self.make_value(value)
        self.current_state.stack_push(v)
        
    def get_stack(self, length, offset = 0):
        return self.current_state.stack_read(offset,length)
    
    def reset_state(self):
        self._simgr = None # state is reset upone requesting simgr
        self._current_state = None
        self.stop_reason = StopReason.NONE
        self._pause = False
        self._function_prototypes = {}
        self._current_function = ''
        self._cfg = None
        self.stop_reason = StopReason.NONE
        self._entry_point = None
#        self._symbols = {}

        log.info("State reset.")
    
    def stop(self):
        self._project = None
        self._simgr = None
        self._current_state = None
 
    # @param handler: StepHandler
    # @param check_until: callable return reason to stop, else None
    # @param exclude: callable returns True to exclude state from active stash
    
    def _run(self, handler:StepHandler, check_until:Callable[[angr.SimulationManager],StopReason] = lambda _:StopReason.NONE, exclude:Callable[[angr.SimState],bool] = lambda _:False, single:bool = False):
        self.throw_if_not_initialized()
        self.stop_reason:StopReason = StopReason.NONE
        #make sure current state is an active state and move it to the front if it is not
        if self.simgr.active:
            if self._current_state not in self.simgr.active:
                self._current_state = self.simgr.one_active
            else:
                #move current state to the front
                if self._current_state != self.simgr.one_active:
                    self.simgr.active.remove(self._current_state)
                    self.simgr.active.insert(0,self._current_state)
        else:
            raise DebuggerCommandError("No active states.")
        
        def selector_func(state):
            #return true if state is the first in the active stash
            return state == self.simgr.one_active  # type: ignore
        
        def filter_func(state):
            if state.addr == 0:
                return "deadended"
            #move excludes states to the exclude list
            if exclude and exclude(state):
                return "excluded"
            return None
        
        def step_func(simgr):
            # handle output
            if simgr.active:
                state = simgr.one_active
                std:StdTracker = state.get_plugin('stdout_tracker')
                std_data = std.get_new_string()
                if std_data:handler.handle_output(std_data)

        def until_func(simgr):
            if not simgr.active:
                self.stop_reason = StopReason.TERMINATE
                return True
            self.stop_reason = check_until(simgr)
            return self.stop_reason != StopReason.NONE
        self.simgr.run(stash="active", selector_func=selector_func, filter_func=filter_func,until=until_func,step_func=step_func, num_inst=1 if single else None)
        self._set_current_state( self.simgr.one_active if self.simgr.active else None)
        handler.handle_step(self.stop_reason, self._current_state)

    def back(self):
        #get the previous state
        if self.simgr.active:
            cur = self.simgr.one_active
            #remove the current state from the active stash
            self.simgr.active.remove(cur)
            #add parent state to the active stash
            if cur.history.parent:
                new_state = cur.history.parent.state.copy()
                self.simgr.active.insert(0,new_state)
                self._set_current_state(new_state)
            else:
                raise DebuggerCommandError("No parent state.")
        elif self.simgr.deadended:
            self._set_current_state(self.simgr.one_deadended)
  
    def get_current_addr(self):
        return self.current_state.addr


    def get_callstack(self,state):
        paths = [] 
        prev = state.addr
        i = 0
        for ix,s in enumerate(state.callstack):
            block = self.project.factory.block(prev)
            f = self.get_function_info(s.func_addr) if s.func_addr!=0 else None
            name = f.name if f else f"State at address{hex(s.func_addr)}"
            end = block.instruction_addrs[-1] if len(block.instruction_addrs) else s.func_addr # type: ignore
            paths.append({"addr":prev, "id":i, "func":s.func_addr, "end": end, "name":  name})
            prev = s.call_site_addr
            i += 1
        return paths

        
    def get_return_value(self)->int|None|claripy.ast.Base:
        prototype = self.get_stored_function(self._current_function)["prototype"]
        cc = self.get_stored_function(self._current_function)["cc"]
        if not cc or prototype.returnty is None:
            return None
        loc = cc.return_val(prototype.returnty)
        if loc is None:
            return None
        state = self.current_state
        val = loc.get_value(state, stack_base=state.regs.sp - cc.STACKARG_SP_DIFF)
        value = state.solver.eval(val, cast_to=int)
        return value
    
    def get_callable_function(self, addr:int):
        return self.project.factory.callable(addr)
 
    def get_bb_end_address(self, state):
        bb = state.block()
        if not bb.instruction_addrs:
            return state.addr
        return bb.instruction_addrs[-1]
    
    def get_bbs(self):
        # TODO: Add filtering support
        #return all basic blocks of the binary including block addr size instructions and capstone based on the CFG
        for node in self.cfg.graph.nodes():
            #include function name if available:
            func = self.cfg.kb.functions.get(node.function_address, None)
            yield BasicBlock(node.addr, node.size, len(node.instruction_addrs), node.block.capstone if node.block else None, func.name if func else None)
    def get_bb_count(self):
        return len(self.cfg.graph.nodes())
        
    def get_current_basic_block(self):
        state = self.current_state
        try:
            block = state.block()
            return BasicBlock(block.addr,block.size,block.instructions,block.capstone) # type: ignore
        except Exception as e:
            raise DebuggerCommandError(f"Failed to retrieve basic block: {e}")
        
    def get_stdstream(self, stream:StreamType):
        return self.current_state.posix.dumps(stream.value)
     
    def create_symbolic_file(self, name:str, content:str|claripy.ast.BV|claripy.ast.String|None=None, size:int|None=None):
        file = angr.storage.file.SimFile(name, content=content, size=size)
        self.current_state.fs.insert(name, file)
    
    def get_stashes(self):
        return list(self.simgr.stashes.keys())
            
    def list_paths(self, stash:str = "active"):
        if stash not in self.simgr.stashes:
            raise DebuggerCommandError(f"Stash {stash} not found.")
        return self.simgr.stashes[stash]
    
    def set_memory(self,address:int|SymBitVector,value:AngrValueType,size:int|None = None, endness:Endness = Endness.DEFAULT):
        if isinstance(value,str):
            # Encode string to bytes
            val = value.encode('utf-8')
        else:
            val = value
        en = Endness.to_arch_endness(endness, self.project)
        # Store the byte value in memory
        self.current_state.memory.store(address, val,size, endness=en,)
    
    def get_memory(self, address:int|SymBitVector, size:int|SymBitVector|None = None, endness:Endness = Endness.DEFAULT):
        state = self.current_state
        if address is int: 
            if size == 0:
                size = self.project.arch.bits // 8
        byte_value = state.memory.load(address, size, endness=Endness.to_arch_endness(endness, self.project))
        return byte_value
    
    def get_addr_for_symbol(self, symbol:str):
        # Letting the user know that certain options have to be set to allow this function.
        required_options = ["REVERSE_MEMORY_NAME_MAP", "TRACK_ACTION_HISTORY"]
        for option in required_options:
            if option not in self.current_state.options:
                raise DebuggerCommandError(f"Make sure you enable '{option}' when setting the entry state")

        return self.current_state.memory.addrs_for_name(symbol)
    
    def get_stream(self, stream:StreamType) -> str:
        state = self.current_state
        mapped = stream.name.lower()
        std:StdTracker = state.get_plugin(f'{mapped}_tracker')
        return std.get_prev_string()

    def cast_to(self, value:AngrValueType, dtype:DataType, **kwargs):
        return dtype.convert(value,  self.project.arch if self.initialized else get_local_arch(), **kwargs)    

    def load_hooks(self, filename):
        mod = load_module_from_file(filename)
        hooks = hook_simprocedures(self.project,mod)
        return hooks
    
    def add_hook(self, address:int, function:Callable, skip_length:int = 0, replace = True):
        self.project.hook(address, function, length=skip_length, replace=replace)

    def add_function_hook(self, target:int|str, function:SimProcedure):
        self.project.hook_symbol(target, function, replace=True)

    def add_to_state(self, name:str, value:AngrType):
        self.current_state.globals[name] = value
    def get_from_state(self, name:str):
        return self.current_state.globals[name]

    def get_constraints(self):
        return self.current_state.solver.constraints
    
    def get_binary_symbols(self):
        symbols = []
        for s in self.project.loader.symbols:
            symbols.append(DebugSymbol(s.name, s.type, s.rebased_addr))
        #remove duplicates
        symbols = list({symbol.name:symbol for symbol in symbols}.values())
        return symbols
    
    def get_decompiled_function(self, func_name):
        func = self.cfg.kb.functions.function(name=func_name)
        if func:
            decompiled = self.project.analyses.Decompiler(func)
            return decompiled.codegen.text if decompiled.codegen else None
        return None

    def get_decompiled_function_at_address(self, start, end):
        if not self._cfg:
            cfg = self.project.analyses.CFGFast(start=start,end=end, force_complete_scan=False, normalize=True)
        else:
            cfg = self._cfg
        decompiled = self.project.analyses.Decompiler(start)
        return decompiled.codegen.text if decompiled.codegen else None

    def get_binary_string_constants(self,min_length=4):
        # _ = self.cfg
        constants = []
        for section in self.project.loader.main_object.sections:
            if section.is_readable:  # Usually data sections
                base_addr = section.vaddr
                size = section.memsize
                if size == 0 or base_addr == 0:
                    continue
                data = self.project.loader.memory.load(base_addr, size)
                # Find all sequences of printable characters in the data
                # Adjust the regex pattern as needed for different types of strings
                re_pattern = rb'[ -~]{%d,}' % min_length
                matches = re.finditer(re_pattern, data)  # Find strings with at least 4 printable characters
                
                for match in matches:
                    # Compute the address of the string in the binary
                    start_offset = match.start()
                    end_offset = match.end()
                    string_value = match.group().decode('utf-8', errors='ignore')  # Decode to UTF-8
                    
                    # Add the string and its address
                    string_address = base_addr + start_offset
                    constants.append((hex(string_address), string_value))

        return constants
    def list_path_history(self, index:int = 0, stash="active"):
        # list basic blocks of states in the path history for both active and deadended states
        st = self.simgr.stashes[stash]
        if index >= len(st):
            raise DebuggerCommandError("Failed to find state")
        state = st[index]

        for a in state.history.recent_bbl_addrs:
                bb = self.project.factory.block(a)
                yield BasicBlock(bb.addr,bb.size,bb.instructions,bb.capstone)
    
    def _get_string_memory_from_state(self, address, state):
        string_array = []
        while True:
            # Read until a null byte is encountered
            endness = state.arch.memory_endness
            byte = state.memory.load(address, 1, endness=endness)
            if state.solver.is_true(byte == 0):
                break
            if not byte.concrete:
                log.error(f"Failed to get concrete value for byte at address {hex(address)}")
                break
            string_array.append(byte.concrete_value)
            address += 1
        str_value = ''.join([chr(byte) for byte in string_array])
        return str_value

    def get_string_memory(self, address):
        return self._get_string_memory_from_state(address, self.current_state)
        
    
    def list_registers(self):
        registers = self.project.arch.registers
        return registers
    
    def get_register_value(self, register):
        size = self.get_register(register)[1]
        value = self.current_state.registers.load(register, size)
        return value
    
    def get_register(self, register):
        if register not in self.project.arch.registers:
            raise DebuggerCommandError(f"Register '{register}' not found.")
        return self.current_state.registers.load(register)

    def set_register(self, register, value:int|claripy.ast.BV):
        self.current_state.registers.store(register, value)

    def visulize_state(self):
        state_printer = StateVisualizer(self.current_state)
        return state_printer.pprint()