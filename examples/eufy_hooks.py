import angr
from angr.sim_options import ABSTRACT_MEMORY

import logging

l = logging.getLogger(name=__name__)
#angr logging is way too verbose
import logging
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = False
    logger.propagate = True

class sscanf(angr.SimProcedure): # find way to use sscanf format strings in python to make more uniform
    def run(self, s, f, g):
        def first():
            self.state.memory.store(self.state.regs.a3, '813806')
            self.state.memory.store(self.state.regs.a3+6, 0)
        def second():
            self.state.memory.store(self.state.regs.a2, self.state.solver.BVV((int)(self.state.mem[s].string.concrete), 8) ) 
        options = {
           b'%[^-]-%[^-]-%s': first,
           b'%x' : second
                           } 
        options[self.state.mem[f].string.concrete]()
        # print("s ", s)
        return None



class gen_dev_rand(angr.SimProcedure): #keep this hooked as it is a neccisary input from the user
    def run(self, arg1, arg2):
        return 59704745


# =================================================================================================================================================================================================================================

class strcat(angr.SimProcedure): #angr stub for strcat
        def run(self,arg1, arg2,arg3):
            strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]
            strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
            dst_len = self.inline_call(strlen, arg1).ret_expr
            src_len = self.inline_call(strlen, arg2).ret_expr

            self.inline_call(strncpy, arg1 + dst_len, arg2, arg3, src_len=src_len)
            return arg1





class memcpy(angr.SimProcedure): # angr stub for memcpy
    # pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        if not self.state.solver.symbolic(limit):
            # not symbolic so we just take the value
            conditional_size = self.state.solver.eval(limit)
        else:
            # constraints on the limit are added during the store
            max_memcpy_size = self.state.libc.max_memcpy_size
            max_limit = self.state.solver.max_int(limit)
            min_limit = self.state.solver.min_int(limit)
            conditional_size = min(max_memcpy_size, max(min_limit, max_limit))
            if max_limit > max_memcpy_size and conditional_size < max_limit:
                l.warning(
                    "memcpy upper bound of %#x outside limit, limiting to %#x instead", max_limit, conditional_size
                )

        l.debug("Memcpy running with conditional_size %#x", conditional_size)

        if conditional_size > 0:
            src_mem = self.state.memory.load(src_addr, conditional_size, endness="Iend_BE")
            if ABSTRACT_MEMORY in self.state.options:
                self.state.memory.store(dst_addr, src_mem, size=conditional_size, endness="Iend_BE")
            else:
                self.state.memory.store(dst_addr, src_mem, size=limit, endness="Iend_BE")

        return dst_addr



class sprintf(angr.SimProcedure): #stubbed this function to get the key out of it
    def run(self, arg1, arg2, arg3):

        format_string = self.state.mem[arg2].string.concrete

        if(format_string == b'%d'):
            self.state.memory.store(arg1, str(arg3.v))
        elif(format_string == b'%02X') :
            self.state.memory.store(arg1, format(arg3.v, "02X") )

        else:
            self.state.memory.store(arg1, arg3)
        return None

