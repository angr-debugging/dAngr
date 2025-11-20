import angr, copy
from dAngr.exceptions import DebuggerCommandError
from angr.state_plugins.globals import SimStateGlobals

def create_stash_if_absent(simgr:angr.SimulationManager, name: str):
    if name not in simgr.stashes:
        simgr.stashes[name] = []
    else:
        raise DebuggerCommandError("Debug name is not unique!")
    return simgr.stashes[name]

class StateHistory():
    def __init__(self, simgr:angr.SimulationManager|None, buffer_size:int, stash_name:str="history"):
        if(simgr == None):
            raise DebuggerCommandError("State needs to be defined!")
        create_stash_if_absent(simgr, stash_name)
        self.stash_name = stash_name
        self.buffer_size = buffer_size

    def save_copy_state(self, simgr:angr.SimulationManager|None, state:angr.SimState|None):
        if(state == None or simgr == None):
            raise DebuggerCommandError("State and Simgr needs to be defined!")
        stash = simgr.stashes[self.stash_name]

        s_copy = state.copy()
        s_copy.register_plugin("globals", SimStateGlobals(copy.deepcopy(dict(state.globals))))

        stash.append(s_copy)

        if len(stash) > self.buffer_size:
            del stash[:-self.buffer_size]

    def go_back_in_history(self, steps:int, simgr:angr.SimulationManager|None):
        if(simgr == None):
            raise DebuggerCommandError("Simgr needs to be defined!")
        stashes = simgr.stashes
        if self.stash_name not in stashes:
            raise DebuggerCommandError(f"Unknown history stash '{self.stash_name}'")

        stash = stashes[self.stash_name]

        if not stash:
            raise DebuggerCommandError("History is empty")

        idx = len(stash) - 1 - steps
        if idx < 0 or idx >= len(stash):
            raise DebuggerCommandError(
                f"steps ({steps}) out of range for history of size {len(stash)}"
            )
        
        chosen_state = stash[idx]
        del stash[idx:]

        # Remove current active state
        active = stashes.setdefault("active", [])
        if active:
            del active[0]
        active.insert(0, chosen_state)

