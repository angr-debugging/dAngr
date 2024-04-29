import asyncio
import os
from typing import List
import angr
from angr.knowledge_plugins.functions import Function
import claripy



from .stdout_tracker import StdoutTracker
from .utils import get_function_by_addr, hook_simprocedures, load_module_from_file

from dAngr.cli.models import BasicBlock, DebugSymbol, State, Response
from dAngr.exceptions import DebuggerCommandError
import logging

from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError


l = logging.getLogger(name=__name__)
#angr logging is way too verbose
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = False
    logger.propagate = True


class Debugger:
    def __init__(self) -> None:
        self._binary_path:str = None
        self._project:angr.project.Project = None
        self._simgr:angr.sim_manager.SimulationManager = None
        self._default_state_options = set([angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS])
        self._pause = False
        self._condition:asyncio.Condition = asyncio.Condition()
        self.base_addr = 0x400000
        self.function_prototypes = {}
        self.current_function = None

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
    
    async def _is_paused(self):
        async with self._condition:
            return self._pause
        
    def get_source_info(self, addr):
        try:
            elf = self._project.loader.find_object_containing(addr)
            src = max(elf.addr_to_line[addr])
            return self.substitute_path_inverse(src[0]), src[1]
        except KeyError:
            return None,0
        
    def _find_elf_object_by_source(self, sourcefile, line_number):
        # Iterate through all ELF objects loaded by the project's loader
        for elf_obj in self._project.loader.all_elf_objects:
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
        self.function_prototypes[name] = {"prototype":angr.sim_type.SimTypeFunction(sim_arg_types, sim_return_type)}
    def store_function(self, name, prototype, addr, cc):
        self.function_prototypes[name] = {"prototype":prototype, "addr":addr, "cc":cc}

    def get_cc(self):
        return angr.default_cc(self._project.arch.name, platform=self._project.simos.name if self._project.simos is not None else None)(self._project.arch)
    def get_stored_function(self, name:str):
        return self.function_prototypes.get(name) if name in self.function_prototypes else None
    
    def set_current_function(self, name:str):
        self.current_function = name
    
    def get_function_cc(self):
        return angr.default_cc(self._project.arch.name, platform=self._project.simos.name if self._project.simos is not None else None)(self._project.arch)
    
    def get_function_info(self, func_addr) -> Function:
       return get_function_by_addr(self._project, func_addr)
    
    def get_function_prototype(self, prototype:str, arguments:List[str]):
        return angr.SimCC.guess_prototype(arguments, prototype).with_arch(self.debugger.project.arch)
    
    def get_function_address(self, function_name):
        for symbol in self._project.loader.main_object.symbols:
            if symbol.name == function_name:
                return symbol.rebased_addr
        return None
    
    def get_variables(self, func_addr):
        names = list(self._project.kb.dvars._dvar_containers)
        pc = claripy.BVV(func_addr+self.base_addr,64) # self._simgr.active[0].ip
        vars = []
        for name in names:
            
            v = self._project.kb.dvars._dvar_containers[name].from_pc(pc)
            if v:
                vars.append(v)
        return vars
    
    def has_dwarf(self):
        return self._project.loader.main_object.has_dwarf_info 

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
    
    def init(self, binary_path:str, from_src_path=None, to_src_path=None, address = None): #support passing custom angr arguments to project
        self._binary_path = binary_path
        self.from_src_path = os.path.abspath(os.path.expanduser(os.path.normpath(from_src_path))) if from_src_path else ''
        self.to_src_path = os.path.abspath(os.path.expanduser(os.path.normpath(to_src_path))) if to_src_path else ''
        if not os.path.exists(binary_path):
            raise InvalidArgumentError(f"File {binary_path} does not exist")
        self._project = angr.Project(binary_path, load_options={'auto_load_libs': False, 'load_debug_info': True}) #,'main_opts':{'base_addr': 0x400000}})
        self._project.kb.dvars.load_from_dwarf()
        
        # self._simgr.stashes["deferred"] = []

        if address:
            state = self._project.factory.entry_state(addr=address, add_options=self._default_state_options)
            self._simgr = self._project.factory.simulation_manager(state)
        else:
            state = self._project.factory.entry_state(add_options=self._default_state_options)
            self._simgr = self._project.factory.simulation_manager(state)        
        state.register_plugin('stdout_tracker', StdoutTracker())
        self._pause=False
        

    def reload(self):
        if self._binary_path is None:
            raise DebuggerCommandError("Binary not loaded.")
        f = self._binary_path
        self.stop()
        self.init(f)

    def getCFGFast(self):
        return self._project.analyses.CFGFast()

    def init_function_call(self, addr, prototype, cc, arguments):
        self._pause=False
        state = self._project.factory.call_state(
            addr,
            *arguments,
            prototype=prototype,
            cc=cc,
            base_state=None,
            ret_addr=self._project.simos.return_deadend,
            toc=None,
            add_options=self._default_state_options,
            remove_options=None,
        )
        self._simgr = self._project.factory.simulation_manager(state)
        self._simgr.stashes["deferred"] = []
        state.register_plugin('stdout_tracker', StdoutTracker())
        self._pause=False

    def is_initialized(self):
        return self._project is not None
    
    def is_active(self,all=False):
        if all:
            return self._simgr and len(self._simgr.active)>0 and len(self._simgr.deadended)==0
        else: # there may be inactive states
            return self._simgr and len(self._simgr.active)>0
    
    def is_finished(self, all=False):
        if all:
            return self._simgr and len(self._simgr.deadended)>0 and len(self._simgr.active)==0
        else: # there may be active states
            return self._simgr and len(self._simgr.deadended)>0
    
    def stop(self):
        self._project = None
        self._simgr = None
        self._pause = False



    def select_active_path(self, index):
        to_move = self._simgr.stashes["active"][index]
        self._simgr.move(from_stash="active", to_stash="deferred")
        self._simgr.move("deferred", to_stash="active", filter_func= lambda x: x==to_move)
        return (to_move)  

    async def step(self, handler):

        if len(self._simgr.stashes["active"])>1:
            raise DebuggerCommandError("More than one active state, use the list_active_path command")
                
        while True:
            #TODO: check if we need to defer potentially multiple states?
   

            self._simgr.step()
            if len(self._simgr.stashes["active"])>1:
                raise DebuggerCommandError("More than one active state, use the list_active_path command")
            if len(self._simgr.active)==0: 
                break

            addr = self._simgr.active[0].addr
            # proceed if the address is not in the main object
            if self._project.loader.main_object.contains_addr(addr):
                break

        for idx, state in enumerate(self._simgr.active):
            #print(f"step: ${hex(state.addr)}")
            stdout_data = state.get_plugin('stdout_tracker').get_new_output()
            # generate output event
            if stdout_data:
                await handler(stdout_data.decode('utf-8'))

    def get_state_id(self, a):
        if self._simgr is None:
            raise DebuggerCommandError("Execution not started.")
        return next((ix for ix,state in enumerate(self._simgr.active) if state.addr == a), None)
    
    def get_current_addr(self,stateID=0):
        state = self.get_current_state(stateID)
        return state.addr if state else None


    def get_callstack(self,id:int=0):
        paths = []
        if id >= len(self._simgr.active):
            raise DebuggerCommandError("Failed to find state")
        state:angr.SimState = self._simgr.active[id]
        paths = [] 
        prev = state.addr
        i = 0
        for ix,s in enumerate(state.callstack):
            block = self._project.factory.block(prev)
            f = self.get_function_info(s.func_addr) if s.func_addr!=0 else None
            name = f.name if f else f"State at address{hex(s.func_addr)}"
            end = block.instruction_addrs[-1] if len(block.instruction_addrs) else s.func_addr
            paths.append({"addr":prev, "id":i, "func":s.func_addr, "end": end, "name":  name})
            prev = s.call_site_addr
            i += 1
        return paths

        
    def get_return_values(self, stateID=0):
        vals = []
        prototype = self.get_stored_function(self.current_function)["prototype"]
        cc = self.get_stored_function(self.current_function)["cc"]
        if not cc or prototype.returnty is None:
            return vals
        loc = cc.return_val(prototype.returnty)
        if loc is None:
            return vals # no return value
        
        for state in self._simgr.deadended:
            val = loc.get_value(state, stack_base=state.regs.sp - cc.STACKARG_SP_DIFF)
            val = state.solver.simplify(val)
            if val.concrete:
                val = val.concrete_value
            vals.append(val)
        return vals
       
    def get_bb(self, state):
        return self._project.factory.block(state.addr)

    def get_bb_end_address(self, state):
        bb = self._project.factory.block(state.addr)
        if not bb.instruction_addrs:
            return state.addr
        return bb.instruction_addrs[-1]

    async def run(self, breakpoints, handler, until = None):
        
        if self._simgr is None:
            raise DebuggerCommandError("Execution not started.")
        
        await self.pause(False)
        while True:
            await self.step(handler.handle_output)

            if await self._is_paused():
                await handler.handle_pause(next((s.addr for s in self._simgr.active),None))
                return
                
            # Check for forks that require interaction
            if len(self._simgr.active) > 1:
                await handler.handle_pause(next((s.addr for s in self._simgr.active),None))
                return
            
            # Check for breakpoints
            # if there is a breakpoint between the start or end of the block, return the corresponding state
            # first retrieve the end of the block
            blocks = [(state.addr, self.get_bb_end_address(state)) for state in self._simgr.active]
            blocks = [(start, end) for start, end in blocks if any(start <= bp <= end for bp in breakpoints)]


            #states = {active for active in self._simgr.active if active.addr in breakpoints}
            if len(blocks) > 0 :
                await handler.handle_breakpoint([b for b in breakpoints if any(start <= b <= end for start, end in blocks)])
                return

            if not self._simgr.active:
                if self._simgr.deadended:
                    await handler.handle_exit()
                return
            
            if until!= None and until():
                await handler.handle_step(next((s.addr for s in self._simgr.active),None))
                return
            
    def get_paths(self):
        return self._simgr.active + self._simgr.stashes["deferred"]
    
    
    def get_current_basic_block(self, stateID = 0):
        state = self.get_current_state(stateID)
        try:
            block = self.get_bb(state)
            return BasicBlock(block.addr,block.size,block.instructions,block.capstone)
        except Exception as e:
            raise DebuggerCommandError(f"Failed to retrieve basic block: {e}")

    
    def set_memory(self,address,value,stateID=0):
        state = self.get_current_state(stateID)
        if type(value) == int:
            # Account for endianness when storing integers
            if self._project.arch.memory_endness.replace('Iend_', '').lower()=='le':
                endianness = 'little'
            else:
                endianness = 'big'
            byte_value = value.to_bytes(self._project.arch.bits // 8, byteorder=endianness)
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
        state.memory.store(address, byte_value)
    
    def get_memory(self, address, size, stateID=0):
        state = self.get_current_state(stateID)
        byte_value = state.memory.load(address, size)
        return byte_value
    
    def get_int_memory(self, address, stateID=0):
        state = self.get_current_state(stateID)
        return self.get_memory(address, state.arch.bytes, stateID)

    def cast_to(self, value, cast_to, stateID=0):
        if not value.concrete:
            raise DebuggerCommandError("Value is not concrete.")
        state = self.get_current_state(stateID=stateID)

        if cast_to == bytes:
            return state.solver.eval(value, cast_to=cast_to)
        elif cast_to == int:
            return int.from_bytes(state.solver.eval(value, cast_to=bytes), byteorder="little" if self._project.arch.memory_endness.replace('Iend_', '').lower()=='le' else 'big')
    def cast_to_bytes(self, value):
        if type(value) == int:
            # Account for endianness when storing integers
            if self._project.arch.memory_endness.replace('Iend_', '').lower()=='le':
                endianness = 'little'
            else:
                endianness = 'big'
            byte_value = value.to_bytes(self._project.arch.bytes, byteorder=endianness)
        elif type(value) == str:
            # Encode string to bytes
            byte_value = value.encode('utf-8')
        elif type(value) == bytes:
            # Evaluate the bytes literal
            byte_value = eval(value)
            if not isinstance(byte_value, bytes):
                raise DebuggerCommandError("Value is not a byte array.")
        else:
            raise DebuggerCommandError(f"Type not supported. Use 'int', 'str', or 'bytes'.")
        return byte_value
    def load_hooks(self, filename):
        mod = load_module_from_file(filename)
        hooks = hook_simprocedures(self._project,mod)
        return hooks
    
    def get_constraints(self, stateID=0):
        state = self.get_current_state(stateID)
        return state.solver.constraints
    
    def get_binary_symbols(self):
        symbols = []
        for s in self._project.loader.main_object.symbols:
            symbols.append(DebugSymbol(s.name, s.type, s.rebased_addr))
        return symbols
    
    def list_path_history(self):
        # list states in the path history for both active and deadended states
        # TODO: check creation of path history
        states ={}
        for index, state in enumerate(self._simgr.active):
            if "active" + str(index) not in states:
                states["active" + str(index)] = []
            for action in state.history.actions:
                if action.action_type == 'execution':
                    states["active" + str(index)].append(BasicBlock(action.bbl_addr))
            states["active" + str(index)].append(State(str(index), state.addr))
        for index, state in enumerate(self._simgr.deadended):
            if "deadended" + str(str(index)) not in states:
                states["deadended" + str(index)] = []
            for action in state.history.actions:
                if action.action_type == 'execution':
                    states["deadended" + str(index)].append(BasicBlock(action.bbl_addr))
            states["deadended" + str(index)].append(State(str(index), state.addr, True))
        return states
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
        if len(self._simgr.active) > stateID:
            state = self._simgr.active[stateID]
        else:
            state = self._simgr.deadended[stateID]
        return state
    def get_string_memory(self, address, stateID=0):
        #hack to get the state
        state = self.get_current_state(stateID)
        return self._get_string_memory_from_state(address, state)
        
    
    def list_registers(self):
        registers = self._project.arch.registers
        return registers
    
    def get_register_value(self, register, size, stateID=0):
        state = self.get_current_state(stateID)
        value = state.registers.load(register, size // 8)
        return value
    
    def get_register(self, register):
        if register not in self._project.arch.registers:
            raise DebuggerCommandError(f"Register '{register}' not found.")
        return self.list_registers()[register]

    def set_register(self, register, value, stateID=0):
        state = self.get_current_state(stateID)
        r = self.get_register(register)
        state.registers.store(r[0], value)