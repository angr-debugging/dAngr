import asyncio
import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.angr_ext.step_handler import StopReason
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.script_processor import ScriptProcessor
from dAngr.exceptions import DebuggerCommandError, ExecutionError
import angr

from dAngr.utils.loggers import AsyncLogger

log = AsyncLogger("execution")

class ExecutionCommands(BaseCommand):
    
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
    
    async def continue_(self): # type: ignore
        """
        Run until a breakpoint or terminated. Same as run.

        Short name: c
        """
        await super().run_angr()
    
    async def run(self): # type: ignore
        """
        Run until a breakpoint or terminated. Same as continue.

        Short name: c
        """
        await super().run_angr()

    async def step_out(self):  # type: ignore
        """
        Step out of the current function.

        Short name: sO
        """
        cs0 = self.debugger.get_callstack(self.debugger.current_state)
        def check_call_stack(simgr)->StopReason:
            cs = self.debugger.get_callstack(simgr.one_active)
            if len(cs) < len(cs0):
                return StopReason.STEP
            return StopReason.NONE

        await super().run_angr(check_call_stack) # return immediately

    async def step_over(self): # type: ignore        
        """
        Step over the current statement.

        Short name: so
        """
        cs0 = self.debugger.get_callstack(self.debugger.current_state)
        def check_call_stack(simgr)->StopReason:
            cs = self.debugger.get_callstack(simgr.one_active)
            if len(cs)!= len(cs0):
                return StopReason.NONE
            for i in range(0,len(cs)):
                if cs[i]['func']!= cs0[i]['func']:
                    return StopReason.NONE
            return StopReason.STEP

        await self.run_angr(check_call_stack) # return immediately

    async def step(self): # type: ignore
        """
        Take a next debugging step.

        Short name: s
        """
        await super().run_angr(lambda _: StopReason.STEP) # return immediately

    async def exit(self):
        """
        Exit the debugger.

        Short name: q
        """
        self.debugger.stop()

    async def load_hooks(self, filename:str):
        """
        Load hooks from a file.

        Args:
            filename (str): The python file containing the hooks to load.

        Example:
            class printf(angr.SimProcedure): 
                def run(self, args):
                    print(f"Running hooked print function in example_hooks.py: {args}")
                    return
        
        Short name: lh
        """
        self.debugger.load_hooks(filename)
        await self.send_info(f"Hooks '{filename}' successfully attached.")
   
    async def add_hook(self,  definition:str, location:int|str, skip_length:int = 0):
        """
        Add a hook at a specific location.

        Args:
            definition (str): The definition of the hook.
            location (int|str): The location to add the hook (int for an address, string for a function name).
            skip_length (int): The length of the instruction to skip. Default is 0.

        Short name: ah
        """
        if isinstance(location, str):
            address = self.debugger.get_function_address(location)
            if not address:
                raise DebuggerCommandError(f"Function '{location}' not found.")
        else:
            address = location
        func = self.debugger.context.get_definition(definition)
        def run_sync(state,*args):
            try:
                prev = self.debugger.current_state
                self.debugger.current_state = state
                loop = asyncio.get_event_loop()
                v = loop.run_until_complete(func(self.debugger.context, *args))
            finally:
                self.debugger.current_state = prev
        
        self.debugger.add_hook(address, run_sync , skip_length)
        await self.send_info(f"Hook added at {location}.")

    async def load(self, binary_path:str, base_addr:int=0):
        """
        Load a binary into the debugger.

        Args:
            binary_path (str): The path to the binary to load.
            base_addr (int): The base address of the binary. Default is 0, means the binary is loaded at its default base address.

        Short name: l
        """
        try:
            self.debugger.init(binary_path, base_addr)
        except Exception as e:
            raise DebuggerCommandError(f"Failed to load binary: {e}")
        f = os.path.basename(binary_path)
        await self.send_info(f"Binary '{f}' loaded.")

    async def pause(self):
        """
        Pause the debugger.

        Short name: p
        """
        await self.debugger.pause()
        await self.send_info("Paused successfully.")

    async def reset_state(self):
        """
        Restart the debugger to the entry state.

        Short name: r
        """
        self.debugger.reset_state()
        entry_point = self.debugger.entry_point
        if entry_point is None:
            await self.send_info("State reset.")
        else:
            s = f"address {hex(entry_point)}" if isinstance(entry_point, int) else f"to function {entry_point[0]} with arguments {[str(a) for a in entry_point[3]]}"
            await self.send_info(f"State reset at entry point {s}.")


    async def run_script(self, script_path:str):
        """
        Run a script.

        Args:
            script_path (str): The path to the script to run.

        Short name: dangr
        """
        # read the script and call handler for each non-empty, non-comment line
        try:
            log.debug(lambda: f"running script {script_path} in folder" + os.getcwd())
            for line in ScriptProcessor(script_path).process_file():
                if not line.strip().startswith("#"):
                    log.debug(lambda: f"running following line: {line}")
                    if line == "less":
                        continue
                    if not await self.debugger.handle(line):
                        break
        except Exception as e:
            raise DebuggerCommandError(f"Failed to run script: {e}", e)


    async def select_path(self, index:int, stash:str="active"):
        """
        Select a path to execute.

        Args:
            index (int): The index of the path to select as shown in list_active_paths.
            stash (str): The stash to select the path from. Default is active.
        
        Short name: sp
        """
        self.debugger.set_current_state(index, stash)
        await self.send_info(f"Path {index} selected: {hex(self.debugger.current_state.addr)}") # type: ignore

    async def move_state_to_stash(self, index:int, from_stash:str, to_stash:str):
        """
        Move a state from one stash to another.

        Args:
            index (int): The index of the state to move.
            from_stash (str): The stash to move the state from.
            to_stash (str): The stash to move the state to.

        Short name: msts
        """
        self.debugger.move_state_to_stash(index, from_stash, to_stash)
        await self.send_info(f"State moved from {from_stash} to {to_stash}.")

    async def set_start_address(self, address:int):
        """
        Set the start address for execution.

        Args:
            address (int): The address to start execution at.
        
        Short name: e
        """
        self.debugger.set_start_address(address)
        await self.send_info(f"Execution will start at address {hex(address)}.")
