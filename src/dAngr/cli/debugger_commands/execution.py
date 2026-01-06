import inspect
import os

from prompt_toolkit import ANSI
from dAngr.angr_ext.debugger import Debugger
from dAngr.angr_ext.step_handler import StopReason
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.grammar.definitions import FunctionDefinition
from dAngr.cli.script_processor import ScriptProcessor
from dAngr.exceptions import DebuggerCommandError
from dAngr.utils import AngrType
import angr

from dAngr.utils.loggers import AsyncLogger

log = AsyncLogger("execution")

class ExecutionCommands(BaseCommand):
    
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
    
    # def continue_(self): # type: ignore
    #     """
    #     Run until a breakpoint or terminated. Same as run.

    #     Short name: c
    #     """
    #     super().run_angr()
    
    def run(self): # type: ignore
        """
        Run until a breakpoint or terminated. Same as continue.

        Short name: c
        """
        super().run_angr()

    def step_out(self):  # type: ignore
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

        super().run_angr(check_call_stack) # return immediately

    def step_over(self): # type: ignore        
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
                if cs[i].function_address != cs0[i].function_address:
                    return StopReason.NONE
            return StopReason.STEP

        self.run_angr(check_call_stack) # return immediately

    def step(self): # type: ignore
        """
        Take a next debugging step (per basic block).

        Short name: s
        """
        super().run_angr(lambda _: StopReason.STEP) # return immediately
        if self.debugger.verbose_step:
            pstr_state = self.debugger.visualize_state()
            self.send_result(ANSI(pstr_state))
        # Throws errors in example 14 of malware analysis
        #return self.debugger.get_current_basic_block() 
    
    def single_step(self):
        """
        Take a next debugging step (per instruction).

        Short name: ss
        """
        super().run_angr(lambda _: StopReason.STEP, single_step=True)
        if self.debugger.verbose_step:
            pstr_state = self.debugger.visualize_state()
            self.send_result(ANSI(pstr_state))

    def get_callable_function(self, addr: int, *args):
        """
        Get a callable function.

        Args:
            addr (int): The address of the function to get.
            args (tuple): The arguments to pass to the function.

        Short name: gcf
        """
        function = self.debugger.get_callable_function(addr)
        return function(*args) 
    
    def exit(self):
        """
        Exit the debugger.

        Short name: q
        """
        self.debugger.stop()

    def load_hooks(self, filename:str):
        """
        Load hooks from a file.

        Args:
            filename (str): The python file containing the hooks to load.

        Example:
            class printf(angr.SimProcedure): 
                def run(self, args):
                    print(f"Running hooked print function in example_hooks.py: {args}")
                    return
        
        Short name: hl
        """
        self.debugger.load_hooks(filename)
        self.send_info(f"Hooks '{filename}' successfully attached.")


   
    
    def _generate_simProcedure(self, func:FunctionDefinition):
        from dAngr.cli.command_line_debugger import CommandLineDebugger
        def generate_function(func):
            def run(self, *args):
                self._run(*args)
            params = [inspect.Parameter(a.name, inspect.Parameter.POSITIONAL_OR_KEYWORD) for a in func.args]
            signature = inspect.Signature([inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD)] +params)
            run.__signature__ = signature
            return run
        class CustomSimProcedure(angr.SimProcedure):
            def __init__(self, debugger, func):
                self.debugger = debugger
                self.func:FunctionDefinition = func
                super().__init__()
            def _run(self, *args):
                prev = self.debugger.current_state
                try:
                    self.debugger.current_state = self.state
                    return func(self.debugger.context, *args)
                finally:
                    self.debugger.current_state = prev

        cls = type('CustomSimProcedure_'+func.name, (CustomSimProcedure,), {
            'run': generate_function(func)
        })
        return cls(self.debugger, func)

    def _get_standard_lib(self, func):
        if "." in func:
                lib, func = func.split(".")
        else: lib= 'libc'
        return angr.SIM_PROCEDURES[lib][func]()

    def hook_function(self,  definition:str, target:int|str):
        """
        Add a hook to replace complete function/symbol.

        Args:
            definition (str): The definition of the hook. Standard sim procedures can be addressed as [lib].[func] e.g. libc.printf
            target (int|str): The target to add the hook (int for an address, string for a function name).

        Short name: hf
        """
        func = self.debugger.context.find_definition(definition)
        if func:
            if not isinstance(func, FunctionDefinition):
                raise DebuggerCommandError(f"Definition '{definition}' is not a function definition.")
            proc = self._generate_simProcedure(func)
        else:
            proc = self._get_standard_lib(definition)
        self.debugger.add_function_hook(target, proc)
        self.send_info(f"Hook added at {target}.")

    def hook_region(self,  definition:str, location:int|str, skip_length:int = 0, replace:bool = True):
        """
        Add a hook at a specific location/call site, and skip 'skip_length' instructions.

        Args:
            definition (str): The definition of the hook.
            location (int|str): The location to add the hook (int for an address, string for a function name).
            skip_length (int): The length of the instruction to skip. Default is 0.
            replace (bool): replaces the region. Default = True

        Short name: hr
        """
        if isinstance(location, str):
            address = self.debugger.get_function_address(location)
            if not address:
                raise DebuggerCommandError(f"Function '{location}' not found.")
        else:
            address = location
        func = self.debugger.context.find_definition(definition)
        if not func:
            run_sync = self._get_standard_lib(definition)
        else:
            def run_sync(state,*args):
                try:
                    prev = self.debugger.current_state
                    self.debugger._set_current_state(state)
                    return func(self.debugger.context, *args)
                finally:
                    self.debugger._set_current_state(prev)
        
        self.debugger.add_hook(address, run_sync , skip_length, replace)
        self.send_info(f"Hook added at {location}.")

    def add_to_state(self, name:str, value:AngrType):
        """
        Add a value to the current state.

        Args:
            name (str): The name of the value to add.
            value (AngrType): Value to add to the state.

        Short name: sta
        """
        self.debugger.add_to_state(name, value)
        self.send_info(f"Value {value} added to the state.")

    def get_from_state(self, name:str):
        """
        Get a value from the current state.

        Args:
            name (str): The name of the value to get.

        Short name: sg
        """
        return self.debugger.get_from_state(name)

    def load(self, binary_path:str, base_addr:int=0, veritesting:bool=False, **kwargs):
        """
        Load a binary into the debugger.

        Args:
            binary_path (str): The path to the binary to load.
            base_addr (int): The base address of the binary. Default is 0, means the binary is loaded at its default base address.
            veritesting (bool): Enable veritesting. Default is False.
            kwargs (dict): Additional keyword arguments to pass to the angr project.

        Short name: l
        """
        try:
            if veritesting:
                kwargs['veritesting'] = True
            if not os.path.exists(binary_path):
                raise DebuggerCommandError(f"File '{binary_path}' not found.")
            if base_addr:
                kwargs['base_addr'] = base_addr
            
            self.debugger.init(binary_path, **kwargs)
        except Exception as e:
            raise DebuggerCommandError(f"Failed to load binary: {e}")
        f = os.path.basename(binary_path)
        self.send_info(f"Binary '{f}' loaded.")

    def set_entry_state(self, addr:int|None=None, *args, **kwargs):
        """
        Set the call state of a function.

        Args:
            addr (int): The address the state should start at instead of the entry point.
            args (tuple): a list of values to use as the program's argv. May be mixed strings and bitvectors.
            kwargs (dict): a dictionary of additional keyword arguments to pass to the entry_state function.

        Raises:
            DebuggerCommandError: If the function address is not found.
        
        Short name: ses
        """
        self.debugger.set_entry_state(addr, *args, **kwargs)
        self.send_info(f"Execution will start {'at address '+hex(addr) if addr else 'at specified entry point'}.")


    def set_full_state(self, *args, **kwargs):
        """
        Set a full state.

        Args:
            args (tuple): a list of values to use as the program's argv. May be mixed strings and bitvectors.
            kwargs (dict): a dictionary of additional keyword arguments to pass to the entry_state function.

        Short name: sfs
        """
        self.debugger.set_full_state(*args, **kwargs)
        self.send_info(f"Full state set.")
        
    def set_blank_state(self, *args, **kwargs):
        """
        Set a blank state.

        Args:
            args (tuple): a list of values to use as the program's argv. May be mixed strings and bitvectors.
            kwargs (dict): a dictionary of additional keyword arguments to pass to the entry_state function.

        Short name: sbs
        """
        self.debugger.set_blank_state(*args, **kwargs)
        self.send_info(f"Blank state set.")

    def get_current_state(self):
        """
        Get the current state.

        Short name: gcs
        """
        return self.debugger.current_state

    def keep_unconstrained(self, keep:bool=True):
        """
        Keep unconstrained states.

        Args:
            keep (bool): True to keep unconstrained states, False otherwise.

        Short name: ku
        """
        self.debugger.keep_unconstrained = keep
        self.send_info(f"Unconstrained states {'kept' if keep else 'discarded'}.")

    def pause(self):
        """
        Pause the debugger.

        Short name: p
        """
        self.send_info("Paused successfully.")

    def back(self):
        """
        Go back to the previous state.

        Short name: b
        """
        self.debugger.back()

        self.send_info("Stepped back to: " + hex(self.debugger.current_state.addr) +".") # type: ignore

    def reset_state(self):
        """
        Restart the debugger to the entry state.

        Short name: r
        """
        self.debugger.reset_state()
        entry_point = self.debugger.entry_point
        if entry_point is None:
            self.send_info("State reset.")
        else:
            s = f"address {hex(entry_point)}" if isinstance(entry_point, int) else f"to function {entry_point[0]} with arguments {[str(a) for a in entry_point[3]]}"
            self.send_info(f"State reset at entry point {s}.")


    def run_script(self, script_path:str):
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
                if not line:
                    continue
                if not line.strip().startswith("#"):
                    log.debug(lambda: f"running following line: {line}")
                    if line == "less":
                        continue
                    if not self.debugger.handle(line):
                        break
        except Exception as e:
            raise DebuggerCommandError(f"Failed to run script: {e}", e)


    def select_state(self, index:int|angr.SimState, stash:str="active"):
        """
        Select a path to execute.

        Args:
            index (int|angr.SimState): The index of the path to select as shown in list_active_paths.
            stash (str): The stash to select the path from. Default is active.
        
        Short name: sp
        """
        if isinstance(index, angr.SimState):
            self.debugger.current_state = index
        else:
            self.debugger.set_current_state(index, stash)
        try:
            addr = f": {hex(self.debugger.current_state.addr)}" # type: ignore
        except angr.errors.SimValueError as e:
            addr = ""

        self.send_info(f"Path {index} selected{addr}")

    def move_state_to_stash(self, index:int, from_stash:str, to_stash:str):
        """
        Move a state from one stash to another.

        Args:
            index (int): The index of the state to move.
            from_stash (str): The stash to move the state from.
            to_stash (str): The stash to move the state to.

        Short name: msts
        """
        self.debugger.move_state_to_stash(index, from_stash, to_stash)
        self.send_info(f"State moved from {from_stash} to {to_stash}.")
    
    def move_to_stash(self, stash:str):
        """
        Move a state to a stash.

        Args:
            stash (str): The stash to move the state to.

        Short name: mts
        """
        self.debugger.to_stash(stash)
        self.send_info(f"Current active state moved to {stash}.")

    def undo_step(self, index:int):
        """
        Revert the program by a given number of steps.

        Args:
            index (int): Number of steps to revert.

        Short name: us
        """

        self.debugger.undo_step(index)

    def set_exploration_technique(self, technique:str, **kwargs):
        """
        Set the exploration technique.

        Args:
            technique (str): The exploration technique to set.
            kwargs (dict): Additional keyword arguments to pass to the exploration technique.

        Short name: set
        """
        self.debugger.set_exploration_technique(technique, **kwargs)
        self.send_info(f"Exploration technique set to {technique}.")
        