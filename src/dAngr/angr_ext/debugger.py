import asyncio
import os
import re
from typing import Any, Callable, Dict, List, Tuple, cast
import angr
from angr import SimCC, SimulationManager, types
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.functions.function import Function
import claripy

from dAngr.angr_ext.models import BasicBlock, DebugSymbol
from dAngr.angr_ext.step_handler import StepHandler, StopReason
from dAngr.utils.utils import DEBUG, DataType, StreamType

from .std_tracker import StdTracker
from .utils import create_entry_state, get_function_address, get_function_by_addr, hook_simprocedures, load_module_from_file
from .connection import Connection

from dAngr.exceptions import DebuggerCommandError
import logging

from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError

import nest_asyncio

# Apply the nest_asyncio patch
nest_asyncio.apply()



l = logging.getLogger(name=__name__)
#angr logging is way too verbose
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = False
    logger.propagate = True
    if DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)


class Debugger:
    def __init__(self, conn:Connection) -> None:
        self.conn = conn
        self._binary_path:str|None = None
        self._project:angr.project.Project|None = None
        self._simgr:angr.sim_manager.SimulationManager|None = None
        self._default_state_options = set([angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS])

        self._pause:bool = False
        self._condition:asyncio.Condition = asyncio.Condition()

        self._base_addr:int = 0x400000
        self._function_prototypes = {}
        self._current_function:str = ''
        self._cfg:CFGFast|None = None
        self.stop_reason = StopReason.NONE
        self._entry_point:int|Tuple[str,types.SimTypeFunction,SimCC,List[Any]]|None = None
        self._symbols:Dict[str,int] = {}
        self._synbols_cache:Dict[str,claripy.ast.BV] = {}

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
            #call async function
            asyncio.run(self.conn.send_info("Constructing cfg, this may take a while..."))
            self._cfg = self.project.analyses.CFGFast(normalize=True) 
        return self._cfg

    @property
    def simgr(self)->SimulationManager:
        if self._simgr is None:
            self.throw_if_not_initialized()
            self._simgr,_ = create_entry_state(self.project,self._entry_point,self._default_state_options)
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
    

    async def zero_fill(self, enable:bool=True):
        if enable is None or enable:
            self._default_state_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            self._default_state_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        else:
            if angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY in self._default_state_options:
                self._default_state_options.remove(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
                self._default_state_options.remove(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    async def pause(self,value=True):
        async with self._condition:
            self._pause = value
    
    # def pause_async(self,value:bool):
    #     async def _set_pause(value:bool):
    #         async with self._condition:
    #             self._pause = value
    #     loop = asyncio.get_event_loop()
    #     if loop.is_running():
    #         # If the event loop is already running, use create_task and run it in the loop
    #         future = asyncio.ensure_future(_set_pause(value))
    #         return loop.run_until_complete(future)
    #     else:
    #         return asyncio.run(_set_pause(value))

    @property  
    def is_paused(self):
        async def _is_paused_async():
            async with self._condition:
                return self._pause
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If the event loop is already running, use create_task and run it in the loop
            future = asyncio.ensure_future(_is_paused_async())
            return loop.run_until_complete(future)
        else:
            return asyncio.run(_is_paused_async())
        
    def throw_if_not_initialized(self):
        if self._project is None:
            raise DebuggerCommandError("project not initialized.")
    def throw_if_not_active(self):
        if not self.active:
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
    def find_address(self, sourcefile, line_number):
        n = self._find_elf_object_by_source(self.substitute_path(sourcefile), line_number)
        if n:
            return n[1]
        return None
    
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
    
    def get_function_info(self, func_addr) -> Function|None:
       return get_function_by_addr(self.project, func_addr)
    
    def get_function_prototype(self, prototype:str, arguments:List[str]):
        return angr.SimCC.guess_prototype(arguments, prototype).with_arch(self.project.arch)
    
    def get_function_address(self, name:str):
        return get_function_address(self.project, name)
    
    def get_function_callstate(self, function_name:str, prototype:types.SimTypeFunction, cc:SimCC,arguments:List[Any]):
        self._entry_point = (function_name,prototype,cc,arguments)
        self.reset_state()
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
        return self.project.loader.main_object.has_dwarf_info  # type: ignore

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
    
    def init(self, binary_path:str, entry_point:int|Tuple[str,types.SimTypeFunction,SimCC,List[Any]]|None=None, from_src_path=None, to_src_path=None): #support passing custom angr arguments to project
        self._binary_path = binary_path
        self.from_src_path = os.path.abspath(os.path.expanduser(os.path.normpath(from_src_path))) if from_src_path else ''
        self.to_src_path = os.path.abspath(os.path.expanduser(os.path.normpath(to_src_path))) if to_src_path else ''
        if not os.path.exists(binary_path):
            raise InvalidArgumentError(f"File {binary_path} does not exist")
        self._project = angr.Project(binary_path, load_options={'auto_load_libs': False, 'load_debug_info': True}) #,'main_opts':{'base_addr': 0x400000}})
        self.project.kb.dvars.load_from_dwarf()
    
    
    
    def set_start_address(self, address:int):
        self._simgr = None
        self._entry_point = address
        self.reset_state()
    
    def add_symbol(self, name, size):
        self._symbols[name] = size
    
    def remove_symbol(self,name):
        self._symbols.pop(name)
    
    def get_new_symbol_object(self, name):
        if size := self._symbols.get(name):
            s = claripy.BVS(name, size=size)
            self._synbols_cache[name] = s
            return s
        raise DebuggerCommandError(f"Symbol {name} not found.")
    
    def get_symbol(self, name):
        s = self._synbols_cache.get(name, None)
        if not s is None:
            return s
        raise DebuggerCommandError(f"Symbol {name} not found.")
        
    def reset_state(self):
        self._simgr = None # state is reset upone requesting simgr
        self.stop_reason = StopReason.NONE
    
    def stop(self):
        self._project = None
        self._simgr = None

    def select_active_path(self, index):
        to_move = self.simgr.stashes["active"][index]
        self.simgr.move(from_stash="active", to_stash="deferred")
        self.simgr.move("deferred", to_stash="active", filter_func= lambda x: x==to_move)
        return (to_move)  


    # @param handler: StepHandler
    # @param check_until: callable return reason to stop, else None
    # @param exclude: callable returns True to exclude state from active stash
    
    async def _run(self, handler:StepHandler, check_until:Callable[[angr.SimulationManager],StopReason] = lambda _:StopReason.NONE, exclude:Callable[[angr.SimState],bool] = lambda _:False):
        self.throw_if_not_initialized()
        await self.pause(False)
        self.stop_reason:StopReason = StopReason.NONE
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
                if std_data:
                    loop = asyncio.get_event_loop()
                    future = asyncio.ensure_future(handler.handle_output(std_data))
                    loop.run_until_complete(future)

        def until_func(simgr):
            if not simgr.active:
                self.stop_reason = StopReason.TERMINATE
                return True
            #paused
            if self.is_paused:
                self.stop_reason = StopReason.PAUSE
                return True
            self.stop_reason = check_until(simgr)
            return self.stop_reason != StopReason.NONE
        
        self.simgr.run(stash="active", selector_func=selector_func, filter_func=filter_func,until=until_func,step_func=step_func)
        state = self.simgr.one_active if self.simgr.active else None
        await handler.handle_step(self.stop_reason, state)

            
    # def get_state_id(self, a):
    #     self.throw_if_not_active()
    #     return next((ix for ix,state in enumerate(self.simgr.active) if state.addr == a), None)
    
    def get_current_addr(self,stateID=0):
        state = self.get_current_state(stateID)
        return state.addr if state else None


    def get_callstack(self,id:int=0):
        paths = []
        if id >= len(self.simgr.active):
            raise DebuggerCommandError("Failed to find state")
        state:angr.SimState = self.simgr.active[id]
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

        
    def get_return_value(self, stateID=0)->int|None|claripy.ast.Base:
        prototype = self.get_stored_function(self._current_function)["prototype"]
        cc = self.get_stored_function(self._current_function)["cc"]
        if not cc or prototype.returnty is None:
            return None
        loc = cc.return_val(prototype.returnty)
        if loc is None:
            return None
        if len(self.simgr.active) <= stateID:
            state = self.simgr.deadended[stateID]
            val = loc.get_value(state, stack_base=state.regs.sp - cc.STACKARG_SP_DIFF)
            val = cast(claripy.ast.Base , state.solver.simplify(val))
            if val.concrete:
                val = val.concrete_value
            return val
        return None
 
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
        
    def get_current_basic_block(self, stateID = 0):
        state = self.get_current_state(stateID)
        try:
            block = state.block()
            return BasicBlock(block.addr,block.size,block.instructions,block.capstone) # type: ignore
        except Exception as e:
            raise DebuggerCommandError(f"Failed to retrieve basic block: {e}")
        
    def get_stdstream(self, stream:StreamType):
        state = self.get_current_state()
        return state.posix.dumps(stream.value)
     
        
    
            
    def get_paths(self):
        return self.simgr.active + self.simgr.stashes["deferred"]
    
    def set_memory(self,address:int,value,state = None):

        if type(value) == int:
            # Account for endianness when storing integers
            if self.project.arch.memory_endness.replace('Iend_', '').lower()=='le':
                endianness = 'little'
            else:
                endianness = 'big'
            byte_value = value.to_bytes(self.project.arch.bits // 8, byteorder=endianness)
        elif type(value) == str:
            # Encode string to bytes
            byte_value = value.encode('utf-8')
        elif type(value) == bytes:
            # Evaluate the bytes literal
            if type(value) == str:
                byte_value = eval(value)
            else:
                byte_value = value
            if not isinstance(byte_value, bytes):
                raise DebuggerCommandError("Value is not a byte array.")
        else:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")
        
        # Store the byte value in memory
        if not state:
            state = self.get_current_state()
        state.memory.store(address, byte_value)
    
    def get_memory(self, address, size, stateID=0):
        state = self.get_current_state(stateID)
        byte_value = state.memory.load(address, size)
        return byte_value
    

    def cast_to(self, value:claripy.ast.BV, cast_to:DataType, stateID=0):
        if not value.concrete:
            raise DebuggerCommandError("Value is not concrete.")
        state = self.get_current_state(stateID=stateID)
        if DataType.bytes:
            return state.solver.eval(value, cast_to=bytes)
        if DataType.hex:
            return hex(self.cast_to(value, DataType.int, stateID=stateID)) # type: ignore
        if DataType.str:
            b = state.solver.eval(value, cast_to=bytes)
            return b.decode('utf-8')

        switch = {
            DataType.int: int,
            DataType.bool: bool,
            DataType.double: float,
        }
        cast_to_ = switch.get(cast_to, None)
        if cast_to_ in switch:
            if self.project.arch.memory_endness.replace('Iend_', '').lower()=='le':
                endianness = 'little'
            else:
                endianness = 'big'
            return state.solver.eval(value, cast_to=cast_to_, endness=endianness)
        else:
            raise DebuggerCommandError(f"Invalid data type: {cast_to}.")
        

    def to_bytes(self, value):
        if type(value) == int:
            # Account for endianness when storing integers
            if self.project.arch.memory_endness.replace('Iend_', '').lower()=='le':
                endianness = 'little'
            else:
                endianness = 'big'
            byte_value = value.to_bytes(self.project.arch.bytes, byteorder=endianness)
        elif type(value) == str:
            byte_value = value.encode('utf-8')
        elif type(value) == bytes:
            byte_value = value
        else:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")
        return byte_value
    

    def load_hooks(self, filename):
        mod = load_module_from_file(filename)
        hooks = hook_simprocedures(self.project,mod)
        return hooks
    
    def get_constraints(self, stateID=0):
        state = self.get_current_state(stateID)
        return state.solver.constraints
    
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


    def get_binary_string_constants(self,min_length=4):
        _ = self.cfg
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
            string_array.append(byte.concrete_value)
            address += 1
        str_value = ''.join([chr(byte) for byte in string_array])
        return str_value
    def get_current_state(self, stateID=0):
        #hack to get the state
        if len(self.simgr.active) > stateID:
            state = self.simgr.active[stateID]
        else:
            state = self.simgr.deadended[stateID]
        return state
    def get_string_memory(self, address, stateID=0):
        #hack to get the state
        state = self.get_current_state(stateID)
        return self._get_string_memory_from_state(address, state)
        
    
    def list_registers(self):
        registers = self.project.arch.registers
        return registers
    
    def get_register_value(self, register, size, stateID=0):
        state = self.get_current_state(stateID)
        value = state.registers.load(register, size // 8)
        return value
    
    def get_register(self, register):
        if register not in self.project.arch.registers:
            raise DebuggerCommandError(f"Register '{register}' not found.")
        return self.list_registers()[register]

    def set_register(self, register, value:int|claripy.ast.BV, stateID=0):
        state = self.get_current_state(stateID)
        r = self.get_register(register)
        if isinstance(value, int):
            state.registers.store(r[0], value)
        else:
            state.registers.store(r[0], value)