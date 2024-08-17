import os
from dAngr.angr_ext.debugger import Debugger
from dAngr.angr_ext.step_handler import StopReason
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.exceptions import DebuggerCommandError, ExecutionError
import angr


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
        cs0 = self.debugger.get_callstack()
        def check_call_stack(_)->StopReason:
            cs = self.debugger.get_callstack()
            if len(cs) < len(cs0):
                return StopReason.STEP
            return StopReason.NONE

        await super().run_angr(check_call_stack) # return immediately

    async def step_over(self): # type: ignore        
        """
        Step over the current statement.

        Short name: so
        """
        cs0 = self.debugger.get_callstack()
        def check_call_stack(_)->StopReason:
            cs = self.debugger.get_callstack()
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
   

    async def load(self, binary_path:str):
        """
        Load a binary into the debugger.

        Args:
            binary_path (str): The path to the binary to load.

        Short name: l
        """
        try:
            self.debugger.init(binary_path)
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
            print(os.getcwd())
            with open(script_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        await self.debugger.handle(line)
        except Exception as e:
            raise DebuggerCommandError(f"Failed to run script: {e}")


    async def select_path(self, index:int):
        """
        Select a path to execute.

        Args:
            index (int): The index of the path to select as shown in list_active_paths.
        
        Short name: sp
        """
        state = self.debugger.select_active_path(index)
        if state is None:
            raise DebuggerCommandError("Invalid path index specified.")
        await self.send_info(f"Path {index} selected: {hex(state.addr)}") # type: ignore

    async def set_start_address(self, address:int):
        """
        Set the start address for execution.

        Args:
            address (int): The address to start execution at.
        
        Short name: e
        """
        self.debugger.set_start_address(address)
        await self.send_info(f"Execution will start at address {hex(address)}.")
