from enum import Enum

class MemLocation(Enum):
    STACK = 0
    HEAP = 1
    CODE = 2
    DATA = 3

class Color(Enum):
    RED = 31
    GREEN = 32
    LIGHT_GREEN = 92
    YELLOW = 33
    BLUE = 34
    PURPLE = 35
    CYAN = 36
    WHITE = 37
    GRAY = 90

def to_color(str:str, color:Color):
    c = color.value
    return f"\x1b[{c}m{str}\x1b[0m"
    
class StateVisualizer():
    REGISTERS = {
    8 : ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
    16: ["ax", "bx", "cx", "dx"],
    32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
    64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]}

    def __init__(self, state=None):
        self.state = state
        if state:
            self.bits = state.arch.bits
            # Not really where the stack begins,... 
            self.stack_end = state.registers.load('sp').concrete_value
            bp = state.registers.load('bp')
            if not bp.concrete:
                self.bp = self.stack_end
            else:
                self.bp = bp.concrete_value

            self.stack_begin = state.arch.initial_sp
            
            
            self.heap_start = state.heap.heap_base
            self.heap_end = state.heap.heap_base + state.heap.heap_size
            # state.project.loader.all_objects --> start & end
            self.code_start = state.project.loader.main_object.min_addr
            self.code_end = state.project.loader.main_object.max_addr

    def arch_registers(self, arch_bits):
        return self.REGISTERS[arch_bits]
    
    # (value, (value, ..))
    # TODO stack endness, fix
    def format_value(self, value):
        mem_location = self.check_ref(value)
        if not mem_location:
            return (self.value_to_pstr(value, mem_location), None)
        
        deref_value = self.deref(value, mem_location)
        value = self.value_to_pstr(value, mem_location)
        if deref_value != None:
            deref_value = self.format_value(deref_value)

        return (value, deref_value)
    
    def sybmolic_var_representation(self, svalue):
        return hex(self.state.solver.eval(svalue))

    def value_to_pstr(self, value, mem_location):
        if value == None:
            return value
        if value.uninitialized:
            return to_color(str(value), Color.GRAY)
        elif value.symbolic:
            variable_name = self.sybmolic_var_representation(value)
            return to_color(str(variable_name), Color.LIGHT_GREEN)
        
        value = hex(value.concrete_value)
        if mem_location == MemLocation.STACK:
            return to_color(str(value), Color.PURPLE)
        elif mem_location == MemLocation.HEAP:
            return to_color(str(value), Color.GREEN)
        elif mem_location == MemLocation.CODE:
            return to_color(str(value), Color.RED)
        else:
            return value

    def pprint(self):
        assert self.state is not None
        regs = {}
        for reg in self.REGISTERS[self.bits]:
            value = self.state.registers.load(reg)
            regs[reg] = self.format_value(value)
        
        pstr_regs = self.pprint_registers(regs)
        stack_objs = {}
        for i in range(8):
            offset = int(self.bits/8 * i)
            addr = self.stack_end + offset
            stack_objs[offset] = (addr , self.format_value(self.state.stack_read(offset, int(self.bits/8))))
        pstr_stack = self.pprint_stack(stack_objs)
        pstr_inst = self.pprint_instructions()
        return pstr_regs + "\n" + pstr_stack + "\n" + pstr_inst

    def deref(self, value, mem_location):
        assert self.state is not None
        if mem_location == MemLocation.STACK or mem_location == MemLocation.HEAP:
            return self.state.memory.load(value, int(self.bits/8), endness=self.state.arch.memory_endness)

    # Check if the value is a reference to a value
    def check_ref(self, value):
        if value == None:
            return None
        elif value.symbolic:
            return None
        
        if self.stack_begin >= value.concrete_value >= self.stack_end:
            return MemLocation.STACK
        elif self.heap_start <= value.concrete_value <= self.heap_end:
            return MemLocation.HEAP
        elif self.code_start <= value.concrete_value <= self.code_end:
            return MemLocation.CODE
        else:
            return None
    
    def value_to_str(self, value, res_str="") -> str:
        item, ref = value
        if ref == None:
            return res_str + str(item)
        
        if isinstance(ref, tuple):
            res_str += str(item) + " --> "
            return self.value_to_str(ref, res_str)
        else:
            return res_str + str(item) + " --> " + str(ref)

        

    def pprint_registers(self, registers):
        register_str = "[%s]" % to_color(" Registers ", Color.CYAN).center(78, '-')
        register_str += "\n"
        for register in registers:
            value = registers[register]
            register_str += to_color(f"{register}: ", Color.BLUE)
            register_str += self.value_to_str(value) + "\n"

        return register_str


    # Check if value is 
    def pprint_stack(self, stack_objs):
        assert self.state is not None
        stack_str = "[%s]" % to_color(" Stack ", Color.CYAN).center(78, '-')
        stack_str += "\n"
        for offset in stack_objs:
            stack_str += to_color(f"{offset:04}| ", Color.BLUE)
            addr, value = stack_objs[offset]
            stack_str += f"{to_color(hex(addr), Color.PURPLE)} --> {self.value_to_str(value)}"
            if addr == self.bp:
                stack_str += '  <- bp'
            elif addr == self.stack_end:
                stack_str += '  <- sp'
            stack_str += "\n"
        
        return stack_str
    

    def pprint_instructions(self):
        assert self.state is not None
        instuction_str = "[%s]\n" % to_color(" Basic Block ", Color.CYAN).center(78, '-')
        try:
            block = self.state.block()
            basic_block_ins = block.disassembly.insns
        except Exception as e:
            return f"Error getting instructions: {e}"
        
        if block.size > 10:
            basic_block_ins = basic_block_ins[:10]
        
        for ins in basic_block_ins:
            instuction_str += to_color(f"{hex(ins.address)}: ", Color.RED) + to_color(f"{ins.mnemonic}", Color.GREEN) + "\t" + f"{ins.op_str}"
            instuction_str += "\n" 

        if block.size > 10:
            instuction_str += to_color(f"...\n", Color.GRAY)
        
        return instuction_str
