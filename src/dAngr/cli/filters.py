
from abc import abstractmethod
from typing import List, override

from angr import SimState

from dAngr.angr_ext.std_tracker import StdTracker
from dAngr.cli.models import Breakpoint
from dAngr.exceptions import ExecutionError


class Filter:
    
    @property
    @abstractmethod
    def enabled(self)->bool:
        pass
    
    @enabled.setter
    @abstractmethod
    def enabled(self, value:bool):
        pass

    def filter(self, state:SimState):
        if self.enabled:
            return self._filter(state)
        return False
    
    @abstractmethod
    def _filter(self, state:SimState)->bool:
        pass


class FilterList(Filter):
    def __init__(self):
        super().__init__()
        self.filters = []
    
    @property
    def enabled(self)->bool:
        return all(f.enabled for f in self.filters)
    
    @enabled.setter
    def enabled(self, value:bool):
        for f in self.filters:
            f.enabled = value

    def get_matching_filter(self, state:SimState):
        for f in self.filters:
            if f.filter(state):
                yield f
                
    def append(self, filter:Filter):
        self.filters.append(filter)
    def remove(self, filter:Filter):
        self.filters.remove(filter)
    def clear(self):
        self.filters.clear()
    def __getitem__(self, index:int):
        return self.filters[index]
    def _filter(self, state:SimState):
        return any(f._filter(state) for f in self.filters)
    def __len__(self):
        return len(self.filters)
    def __str__(self) -> str:
        return f"FilterList: {', '.join(str(f) for f in self.filters)}"
    def __iter__(self):
        return iter(self.filters)
    def empty(self):
        return len(self.filters) == 0

class AddressFilter(Filter):
    def __init__(self, address:int):
        super().__init__()
        self.address = address
        self._enabled = True
    
    @property
    def enabled(self)->bool:
        return self._enabled
    
    @enabled.setter
    def enabled(self, value:bool):
        self._enabled = value

    def _filter(self, state:SimState)->bool:
        if self.address == state.addr:
            return True
        # check if in range of block
        start:int = state.addr # type: ignore
        #check if start is in binary
        if not state.project.loader.main_object.contains_addr(start): # type: ignore
            return False
        instrs = state.block().instruction_addrs
        if not instrs:
            return False
        end = instrs[-1] # type: ignore
        return start <= self.address <= end
    
    def __str__(self) -> str:
        return f"Address Filter: {hex(self.address)}"

class FunctionFilter(Filter):
    def __init__(self, function_name):
        super().__init__()
        self.function_name = function_name
        self.f_addr = None
        self._enabled = True
    
    @property
    def enabled(self)->bool:
        return self._enabled
    
    @enabled.setter
    def enabled(self, value:bool):
        self._enabled = value

    def _filter(self, state:SimState):
        if self.f_addr is None:
            self.f_addr = func = state.project.kb.functions(name=self.function_name) # type: ignore
        return self.f_addr == state.callstack.func_addr
    
    def __str__(self) -> str:
        return f"Function Filter: {self.function_name}"
    
class StdStreamFilter(Filter):
    mapping = {0: 'stdin', 1: 'stdout', 2: 'stderr'}
    #stdin, stdout, stderr: 0, 1, 2
    def __init__(self, stream:int, value:str, regex:bool = False):
        super().__init__()

        self.stream = stream
        self.value = value
        self._enabled = True
    
    @property
    def enabled(self)->bool:
        return self._enabled
    
    @enabled.setter
    def enabled(self, value:bool):
        self._enabled = value

    def _filter(self, state:SimState):
        if mapped := self.mapping.get(self.stream):
            std:StdTracker = state.get_plugin(f'{mapped}_tracker')
            std_data = std.get_prev_string()

            return self.value in std_data
        raise ExecutionError(f"Stream {self.stream} not found.")
    
    def __str__(self) -> str:
        return f"Standard Stream Filter: {self.stream}"
    
class InputFileFilter(Filter):
    def __init__(self, path, value:str):
        super().__init__()
        self.path = path
        self.value = value
        self._enabled = True
    
    @property
    def enabled(self)->bool:
        return self._enabled
    
    @enabled.setter
    def enabled(self, value:bool):
        self._enabled = value

    def _filter(self, state:SimState):
        return self.value in str(state.posix.dump_file_by_path(self.path))
    
    def __str__(self) -> str:
        return f"Input File Filter: {self.path}"

class SourceFilter(AddressFilter):
    def __init__(self, address:int, source_file:str, line_nr:int):
        super().__init__(address=address)
        self.source_file = source_file
        self.line_nr = line_nr
        
    def __str__(self) -> str:
        return f"Source Filter: {self.source_file}:{self.line_nr} ({hex(self.address)})"
    
class SymbolicFilter(AddressFilter):
    def __init__(self, address:int):
        super().__init__(address=address)
        self._enabled = True
    
    @property
    def enabled(self)->bool:
        return self._enabled
    
    @enabled.setter
    def enabled(self, value:bool):
        self._enabled = value

    @override
    def _filter(self, state:SimState):
        a = state.mem[self.address].int.resolved
        return state.solver.symbolic(a)
    
    def __str__(self) -> str:
        return f"Symbolic Filter: memory address {hex(self.address)}"
    
# class BreakpointFilter(AddressFilter):
#     def __init__(self, address:int, source_file:str|None=None, line_nr:int|None = None, enabled:bool = True):
#         self.breakpoint = Breakpoint(address,source_file,line_nr,enabled)
#         self.address = address
#         super().__init__(address)
    
#     @property
#     def enabled(self):
#         return self.breakpoint.enabled
    
#     @enabled.setter
#     def enabled(self, value:bool):
#         self.breakpoint.enabled = value
#         self._enabled = value
    
#     def __str__(self) -> str:
#         return f"{str(self.breakpoint)}"   