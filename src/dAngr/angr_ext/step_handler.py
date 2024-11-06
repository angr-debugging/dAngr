from abc import abstractmethod
from enum import Enum, auto

from angr import SimState

class StopReason(Enum):
    STEP = auto()
    BRANCH = auto()
    #PAUSE = auto()
    BREAKPOINT = auto()
    TERMINATE = auto()
    NONE = auto()

class StepHandler:
    
    @abstractmethod
    def handle_output(self, output:str):
        pass

    @abstractmethod
    def handle_step(self, reason:StopReason, state:SimState|None):
        pass
    