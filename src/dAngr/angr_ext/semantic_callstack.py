import angr
from angr.state_plugins import SimStatePlugin

from dAngr.angr_ext.utils import get_function_by_addr, is_plt_stub

from dAngr.utils.loggers import get_logger
log = get_logger(__name__)

class Frame:
    __slots__ = ("func", "caller", "callee", "caller_name", "callee_name", "ret", "simproc", "sp")

    def __init__(
        self,
        sp: int | None,
        callee: int,
        callee_name: str,
        caller: int | None = None,
        caller_name: str = "",
        ret: int | None = None,
        func: int | None = None,
        simproc: str | None = None,
    ):
        # func: semantic function for this frame (usually callee, may differ for tail-calls)
        self.sp = sp
        self.func = func if func is not None else callee
        self.callee = callee
        self.callee_name = callee_name
        self.caller = caller
        self.caller_name = caller_name
        self.ret = ret
        self.simproc = simproc

    def __repr__(self):
        parts = [
            f"sp=0x{self.sp:x}" if self.sp is not None else "sp=None",
            f"func=0x{self.func:x}",
            f"callee=0x{self.callee:x}({self.callee_name})",
        ]
        if self.caller is not None:
            parts.append(f"caller=0x{self.caller:x}({self.caller_name})")
        if self.ret is not None:
            parts.append(f"ret=0x{self.ret:x}")
        if self.simproc is not None:
            parts.append(f"simproc={self.simproc}")
        return "Frame(" + ", ".join(parts) + ")"


class SemanticCallstack(SimStatePlugin):
    """
    frames:         list[Frame] – semantic callstack (bottom → top).
    cfg:            angr CFG instance.
    simproc_stack:  list[(SimProcedure, bool visible)]
                    - visible=True  → this SimProc has a Frame in `frames`
                    - visible=False → internal SimProc (hidden: malloc inside __libc_start_main, strlen inside printf, …)
    """

    def __init__(self, cfg=None, frames=None):
        super().__init__()
        self.frames: list[Frame] = list(frames) if frames else []
        self.cfg = cfg
        self.has_call = False  # whether a call has occurred since last check

    def copy(self, memo):
        new = SemanticCallstack(self.cfg, self.frames)
        new.cfg = self.cfg
        new.has_call = self.has_call
        return new
    
    def add_call(self, sp: int, callee: int, callee_name: str, return_address: int):
        # push a new frame
        top = self.frames[-1] if self.frames else None
        caller_addr = top.func if top else None
        caller_name = top.callee_name if top else ""
        

        self.frames.append(
            Frame(
                sp=sp,
                callee=callee,
                callee_name=callee_name,
                caller=caller_addr,
                caller_name=caller_name,
                ret=return_address,
                func=callee,
                simproc=None,
            )
        )
    def pop_call(self):
        # pop the top frame if return address matches
        if not self.frames:
            return
        top = self.frames[-1]
        return_address = top.ret
        # # check if there is a matching frame with top.ret == ret_addr
        for i in range(len(self.frames)-1, -1, -1):
            if return_address == self.frames[i].func:
                # pop all frames above and including i
                self.frames = self.frames[:i]
                return
        # standard behavior:
        self.frames.pop()
        
    def replace_top_frame(self, callee: int, callee_name: str , sp: int):
        # replace the top frame (for tail-calls)
        if not self.frames:
            return
        if sp != self.frames[-1].sp:
            log.warning(f"Warning: replacing top frame with different SP (old=0x{self.frames[-1].sp:x} new=0x{sp:x} )")
        top = self.frames.pop()
        self.frames.append(
            Frame(
                sp=top.sp,
                callee=callee,
                callee_name=callee_name,
                caller=top.caller,
                caller_name=top.caller_name,
                ret=top.ret,
                func=callee,
                simproc=None,
            )
        )
        

    @staticmethod
    def _name():
        return "sem_stack"


def _get_concrete_sp(state: angr.SimState) -> int | None:
    try:
        sp = state.regs.sp
        if getattr(sp, "symbolic", False) is False:
            return getattr(sp, "concrete_value", None)
    except Exception:
        pass
    return None

def _get_function_by_addr(proj: angr.Project, cfg: angr.analyses.cfg.cfg_base.CFGBase, addr: int) -> angr.knowledge_plugins.Function | None:
    func = cfg.get_any_node(addr)
    if func and func.function_address:
        return func.function_address
    # Fallback: check symbols
    return get_function_by_addr(proj, addr)

def _initialize_first_frame(state: angr.SimState):
    """Initialize the first frame at state creation to capture _start or entry point."""
    sem = state.sem_stack
    if sem.frames:
        # Already initialized
        return

    cfg = sem.cfg
    if cfg is None:
        # Can't initialize without CFG, will be handled later
        return

    sp = _get_concrete_sp(state)
    cur_addr = state.addr
    proj: angr.Project = state.project # type: ignore

    func = _get_function_by_addr(proj, cfg, cur_addr)
    if func is None:
        return

    fname = func.name
    if func.is_plt:
        fname += " (PLT Stub)"

    sem.frames.append(
        Frame(
            sp=sp,
            callee=func.addr,
            callee_name=fname,
            caller=None,
            caller_name="",
            ret=None,
            func=func.addr,
            simproc=None,
        )
    )
    log.debug(f"[init first frame] {fname} @ 0x{cur_addr:x}, SP={f'0x{sp:x}' if sp is not None else 'None'}")


def initialize_semantic_callstack(state: angr.SimState, cfg):
    if not state.has_plugin("sem_stack"):
        state.register_plugin("sem_stack", SemanticCallstack(cfg))

    # Set CFG if provided
    if cfg is not None:
        state.sem_stack.cfg = cfg

    # Initialize the first frame immediately (capture _start or entry point)
    _initialize_first_frame(state)

    # Basic-block transitions
    state.inspect.b("irsb", when=angr.BP_AFTER, action=on_irsb_after)
    state.inspect.b("irsb", when=angr.BP_BEFORE, action=on_irsb_before)    
    state.inspect.b("call", when=angr.BP_AFTER, action=on_call_before)
    # state.inspect.b("call", when=angr.BP_AFTER, action=on_call_after)
    state.inspect.b("return", when=angr.BP_AFTER, action=on_return_before)
    # state.inspect.b("return", when=angr.BP_AFTER, action=on_return_after)

def log_stack(state: angr.SimState, location:str):
    if not state.has_plugin("sem_stack"):
        return
    sem = state.sem_stack
    cfg = sem.cfg
    if cfg is None:
        return
    # get current SP
    stack_ptr = _get_concrete_sp(state)
    addr = state.addr
    if n:= cfg.get_any_node(addr):
        func_addr = n.function_address
        func = _get_function_by_addr(state.project, cfg, func_addr)
        func_name = func.name if func else "unknown"
    else:
        func_addr = 0
        func = None
        func_name = "unknown"
    if state.inspect.simprocedure is not None:
        func_name += f" [SimProc: {state.inspect.simprocedure.display_name}]"
    log.debug(f"{location} - State at 0x{addr:x} in function {func_name} (0x{func_addr:x}), SP={f'0x{stack_ptr:x}' if stack_ptr is not None else 'None'}")
    
def get_function_name(proj: angr.Project, cfg: angr.analyses.cfg.cfg_base.CFGBase, addr: int, simproc:bool) -> str | None:
    func = _get_function_by_addr(proj, cfg, addr)
    if func:
        if simproc:
            return f"{func.name} [SimProc]"
        elif is_plt_stub(proj, func.addr):
            return f"{func.name} (PLT Stub)"
        
        return func.name
    return None
# ---------- SimProcedure handling (outermost visible only) ----------
def on_call_before(state: angr.SimState):
    
    log_stack(state, "+Call")
    if not state.has_plugin("sem_stack"):
        return
    sem:SemanticCallstack = state.sem_stack
    cfg = sem.cfg
    if cfg is None:
        return
    state.sem_stack.has_call = True
    name = get_function_name(state.project, cfg, state.addr, simproc=state.inspect.simprocedure is not None) or f"sub_{state.addr:x}"
    #get return address
    ret_addr = None
    if top := sem.frames[-1] if sem.frames else None:
        func = _get_function_by_addr(state.project, cfg, top.func)
        if func:
            call_sites = func.get_call_sites()
            for cs in call_sites:
                target = func.get_call_target(cs)
                if target == state.addr:
                    ret_addr = func.get_call_return(cs)
                    break
    # push to stack
    sem.add_call(
        sp=_get_concrete_sp(state) or 0,
        callee=state.addr,
        callee_name=name,
        return_address=ret_addr
    )

def on_call_after(state: angr.SimState):
    log_stack(state, "-Call")
def on_return_before(state: angr.SimState):
    log_stack(state, "+Return")
    if not state.has_plugin("sem_stack"):
        return
    sem: SemanticCallstack = state.sem_stack
    cfg = sem.cfg
    if cfg is None:
        return
    state.sem_stack.has_call = True
    # pop from stack
    
    sem.pop_call()    
    
def on_return_after(state: angr.SimState):
    log_stack(state, "-Return")
def on_irsb_before(state: angr.SimState):
    log_stack(state, "+IRSB")
    if not state.has_plugin("sem_stack"):
        return
    sem = state.sem_stack
    cfg = sem.cfg
    if cfg is None:
        return
    state.sem_stack.has_call = False
    
def on_irsb_after(state: angr.SimState):
    log_stack(state, "-IRSB")
    log_stack(state, "+Call")
    if not state.has_plugin("sem_stack"):
        return
    sem: SemanticCallstack = state.sem_stack
    cfg = sem.cfg
    if cfg is None:
        return
    if not state.sem_stack.has_call: # must be tail call
        # replace top frame with current function
        sem.replace_top_frame(
            callee = state.addr,
            callee_name = get_function_name(state.project, cfg, state.addr, simproc=state.inspect.simprocedure is not None) or f"sub_{state.addr:x}",
            sp = _get_concrete_sp(state) or 0,
            
        )
def on_simproc_pre_call(state: angr.SimState):
    log_stack(state, "+SimProc")

def on_simproc_post_call(state: angr.SimState):
    log_stack(state, "-SimProc")


class CallStackEntry:
    def __init__(self, id: int, function_address: int, function_display_name: str | None, return_address: int):
        self.id = id
        self.function_address = function_address
        self.function_display_name = function_display_name
        self.return_address = return_address

    def __repr__(self):
        return f"CallStackEntry(id={self.id}, address=0x{self.function_address:x}, name='{self.function_display_name}', return_address=0x{self.return_address:x})"

    def __str__(self):
        ret = ""
        if self.return_address:
            ret = f" (return 0x{self.return_address:x})"
        if not self.function_display_name:
            return f"[{self.id}] 0x{self.function_address:x}{ret}"
        return f"[{self.id}] {self.function_display_name} (0x{self.function_address:x}{ret})"