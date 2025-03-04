from angr import SimState
from dAngr.angr_ext.filters import Filter
from dAngr.angr_ext.definitions import FunctionDefinition


class FilterFunction(Filter):
    def __init__(self, func, debugger):
        super().__init__()
        self.func:FunctionDefinition = func
        self.debugger = debugger
        self._enabled = True
    
    @property
    def enabled(self)->bool:
        return self._enabled
    
    @enabled.setter
    def enabled(self, value:bool):
        self._enabled = value

    def _filter(self, state:SimState):
        try:
            prev = self.debugger.current_state
            self.debugger.current_state = state
            return self.func(self.debugger.context)
        finally:
            self.debugger.current_state = prev
    
    def __repr__(self) -> str:
        return f"Filter Function: {self.func.name}"
    