
from dAngr.angr_ext.debugger import Debugger
from dAngr.exceptions import ExecutionError
from dAngr.exceptions.InvalidArgumentError import InvalidArgumentError

def get_cmd_name(cls):
    return ''.join(['_'+i.lower() if i.isupper() else i for i in cls.__name__.replace('Command', '')]).lstrip('_')

def get_short_cmd_name(cls):
    return ''.join([i.lower() for i in cls.__name__.replace('Command', '') if i.isupper()])
    
class BaseCommand:
    def __init__(self, debugger:Debugger):
        self.debugger = debugger
        self.arg_specs = []
        self.optional_args = []
        self.info = ""
        self.paused = False
        self.cmd_name = get_cmd_name(self.__class__)
        self.short_cmd_name = get_short_cmd_name(self.__class__)

    def get_example(self):
        args_lst = [f"<{a[0].replace(' ','_')}>"  for a in self.arg_specs]
        options = [f"<{a[0].replace(' ','_')}>"  for a in self.optional_args]
        args = ''
        if args_lst:
            args = ', '.join(args_lst)
        if args and options:
            args += ', ['
            args += ', '.join(options)
            args += ']'
        if args:
            args = " " + args  
            return f"{get_cmd_name(self.__class__)}{args}"
        else:
            return None
    
    def throw_if_not_initialized(self):
        if not self.debugger.is_initialized():
            raise ExecutionError("project not initialized.")
    def throw_if_not_active(self):
        if not self.debugger.is_active():
            raise ExecutionError("Execution not started. First 'load'.")
    def throw_if_not_finished(self):
        if not self.debugger.is_finished():
            raise ExecutionError("Execution not finished.")

    def send_event(self, data):
        return self.debugger.conn.send_event(data)
    
    async def execute(self, args):
        raise NotImplementedError("Each command must implement an execute method")
    
    # handler methods
    async def handle_exit(self):
        await self.send_event("Terminated.")

    async def handle_output(self, output:str):
        await self.debugger.conn.send_output(f"{output}")

    async def handle_breakpoint(self,breakpoints:list[int]):
        bps = ",".join([ str(bp) for bp in self.debugger.breakpoints if bp.address in breakpoints])
        await self.send_event(f"Breakpoints hit: {bps}")
    
    async def handle_pause(self, addr):
        await self.send_event(f"Paused at: {hex(addr)}")

    async def handle_step(self,addr):
        await self.send_event(f"Paused at: {hex(addr)}")

    async def run(self, until = None):
        await self.debugger.run([int(bp.address) for bp in self.debugger.breakpoints if bp.enabled], self, until)