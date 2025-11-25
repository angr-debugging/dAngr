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
    proj = state.project

    func = get_function_by_addr(proj, cfg, cur_addr)
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
    # SimProcedure entry/exit
    # state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=on_simproc_pre_call)
    # state.inspect.b("simprocedure", when=angr.BP_AFTER, action=on_simproc_post_call)
    
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
        func = get_function_by_addr(state.project, cfg, func_addr)
        func_name = func.name if func else "unknown"
    else:
        func_addr = 0
        func = None
        func_name = "unknown"
    if state.inspect.simprocedure is not None:
        func_name += f" [SimProc: {state.inspect.simprocedure.display_name}]"
    log.debug(f"{location} - State at 0x{addr:x} in function {func_name} (0x{func_addr:x}), SP={f'0x{stack_ptr:x}' if stack_ptr is not None else 'None'}")
    
def get_function_name(proj: angr.Project, cfg: angr.analyses.cfg.cfg_base.CFGBase, addr: int, simproc:bool) -> str | None:
    func = get_function_by_addr(proj, cfg, addr)
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
        func = get_function_by_addr(state.project, cfg, top.func)
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
# def on_simproc_pre_call(state: angr.SimState):
#     log_stack(state, "+SimProc")
    # return
    # sem = state.sem_stack
    # sp_obj = state.inspect.simprocedure
    # if sp_obj is None:
    #     return

    # stack_ptr = _get_concrete_sp(state)

    # # Simple rule:
    # #   - If no other SimProc is active → visible (show in stack)
    # #   - If another SimProc is active → internal (hidden)
    # visible = len(sem.simproc_stack) == 0

    # sem.simproc_stack.append((sp_obj, visible))

    # if visible:
    #     # Caller = top frame if any, else None
    #     caller_addr = None
    #     caller_name = ""
    #     if sem.frames:
    #         caller_addr = sem.frames[-1].func
    #         caller_name = sem.frames[-1].callee_name

    #     callee_addr = sp_obj.addr
    #     callee_name = sp_obj.display_name

    #     # sem.frames.append(
    #     #     Frame(
    #     #         sp=stack_ptr,
    #     #         callee=callee_addr,
    #     #         callee_name=callee_name,
    #     #         caller=caller_addr,
    #     #         caller_name=caller_name,
    #     #         ret=None,
    #     #         func=callee_addr,
    #     #         simproc=callee_name,
    #     #     )
    #     # )

    # print(
    #     f"Pre SimProc call: {sp_obj.display_name} "
    #     f"(visible={visible}) SP={f'0x{stack_ptr:x}' if stack_ptr is not None else 'None'}"
    # )


# def on_simproc_post_call(state: angr.SimState):
#     log_stack(state, "-SimProc")
#     return
#     sem = state.sem_stack
#     sp_obj = state.inspect.simprocedure
#     if sp_obj is None or not sem.simproc_stack:
#         return

#     stack_ptr = _get_concrete_sp(state)
#     top_sp, visible = sem.simproc_stack.pop()

#     print(
#         f"Post SimProc return: {sp_obj.display_name} "
#         f"(visible={visible}) SP={f'0x{stack_ptr:x}' if stack_ptr is not None else 'None'}"
#     )
#     return
#     # After SimProc returns, check if we're transitioning to main_object code
#     # IRSB hook won't fire for SimProc→main transitions, so handle it here
#     if visible and sem.cfg is not None:
#         next_addr = state.addr
#         proj = state.project
#         main_obj = proj.loader.main_object
        
#         if main_obj.contains_addr(next_addr):
#             func = get_function_by_addr(proj, sem.cfg, next_addr)
#             if func is not None:
#                 callee_name = func.name
#                 if func.is_plt:
#                     callee_name += " (PLT Stub)"
                
#                 # SimProc is calling into main_object
#                 top = sem.frames[-1] if sem.frames else None
#                 if top is not None and top.simproc == sp_obj.display_name:
#                     print(f"SimProc→main: {sp_obj.display_name} calling {callee_name}")
#                     sem.frames.append(
#                         Frame(
#                             sp=stack_ptr,
#                             callee=func.addr,
#                             callee_name=callee_name,
#                             caller=top.func,
#                             caller_name=top.callee_name,
#                             ret=None,
#                             func=func.addr,
#                             simproc=None,
#                         )
#                     )


# ---------- Main-object transitions (CFG-based, using instruction addresses) ----------

# def _update_frames_on_transition(
#     sem: SemanticCallstack,
#     proj: angr.Project,
#     cfg,
#     prev_ins_addr: int,
#     cur_addr: int,
#     sp_addr: int | None,
# ):
#     frames = sem.frames
#     main_obj = proj.loader.main_object

#     in_main_prev = main_obj.contains_addr(prev_ins_addr)
#     in_main_cur = main_obj.contains_addr(cur_addr)

#     func_prev = get_function_by_addr(proj, cfg, prev_ins_addr) if in_main_prev else None
#     func_cur = get_function_by_addr(proj, cfg, cur_addr) if in_main_cur else None

#     top = frames[-1] if frames else None

#     print(f"  _update: prev=0x{prev_ins_addr:x} cur=0x{cur_addr:x}")
#     print(f"  in_main: prev={in_main_prev} cur={in_main_cur}")
#     print(f"  func_prev={func_prev.name if func_prev else None} func_cur={func_cur.name if func_cur else None}")
#     print(f"  top={top.callee_name if top else None}")

#     # --- 0. both outside main_object: ignore (SimProcs or extern)
#     if not in_main_prev and not in_main_cur:
#         return

#     # --- 1. SimProc → main: A SimProc is calling into main_object code
#     #     This happens when __libc_start_main calls _init, main, etc.
#     #     Top frame will be a SimProc, and we're transitioning to main_object.
#     if (
#         top is not None
#         and top.simproc is not None
#         and in_main_cur
#         and func_cur is not None
#     ):
#         # Don't pop the SimProc frame - it remains as the caller
#         # Add the new main_object function as a child frame
#         callee_addr = func_cur.addr
#         callee_name = func_cur.name
#         if func_cur.is_plt:
#             callee_name += " (PLT Stub)"

#         print(f"SimProc → main: {top.callee_name} calling {callee_name}")
#         frames.append(
#             Frame(
#                 sp=sp_addr,
#                 callee=callee_addr,
#                 callee_name=callee_name,
#                 caller=top.func,
#                 caller_name=top.callee_name,
#                 ret=None,
#                 func=callee_addr,
#                 simproc=None,
#             )
#         )
#         return

#     # --- 2. main → outside main: return from main-object to SimProc/caller
#     #     This happens when a function returns to its SimProc caller
#     if (
#         in_main_prev
#         and not in_main_cur
#         and func_prev is not None
#         and top is not None
#         and top.func == func_prev.addr
#         and top.simproc is None
#     ):
#         print(f"Main returned to caller, popping frame {top.callee_name}")
#         frames.pop()
#         return

#     # --- 3. need both functions for main→main logic
#     if func_prev is None or func_cur is None:
#         print(f"Skipping: func_prev={func_prev}, func_cur={func_cur}")
#         return

#     # same function: intra-procedural, nothing
#     if func_prev.addr == func_cur.addr:
#         return

#     # 3.a) Normal call: prev_ins_addr is a callsite whose target == func_cur
#     call_sites = func_prev.get_call_sites()
#     if prev_ins_addr in call_sites:
#         target_addr = func_prev.get_call_target(prev_ins_addr)
#         if target_addr == func_cur.addr:
#             ret_addr = func_prev.get_call_return(prev_ins_addr)
#             callee_name = func_cur.name
#             if func_cur.is_plt:
#                 callee_name += " (PLT Stub)"
#             caller_name = func_prev.name
#             if func_prev.is_plt:
#                 caller_name += " (PLT Stub)"

#             frames.append(
#                 Frame(
#                     sp=sp_addr,
#                     callee=func_cur.addr,
#                     callee_name=callee_name,
#                     caller=prev_ins_addr,
#                     caller_name=caller_name,
#                     ret=ret_addr,
#                     func=func_cur.addr,
#                     simproc=None,
#                 )
#             )
#             return

#     # 3.b) Return: cur_addr is the known return-site of top frame
#     if top is not None and top.ret is not None and cur_addr == top.ret:
#         print(f"Returning from {top.callee_name}, popping frame")
#         frames.pop()
#         return

#     # 3.c) Tail-call: function changed, not a callsite, not a known return-site
#     callee_name = func_cur.name
#     if func_cur.is_plt:
#         callee_name += " (PLT Stub)"
#     caller_name = func_prev.name
#     if func_prev.is_plt:
#         caller_name += " (PLT Stub)"

#     if top is not None and top.func == func_prev.addr:
#         print(f"Tail-call {func_prev.name} → {func_cur.name}, replacing frame")
#         frames.pop()

#     frames.append(
#         Frame(
#             sp=sp_addr,
#             callee=func_cur.addr,
#             callee_name=callee_name,
#             caller=prev_ins_addr,
#             caller_name=caller_name,
#             ret=None,
#             func=func_cur.addr,
#             simproc=None,
#         )
#     )


# # ---------- IRSB hook: use *instruction* addr as callsite ----------

# def semantic_callstack_instruction_hook(state: angr.SimState):
#     sem = state.sem_stack
#     cfg = sem.cfg
#     if cfg is None:
#         return

#     sp = _get_concrete_sp(state)
#     if sp is None:
#         return

#     proj = state.project
#     cur_addr = state.addr  # address of current basic block

#     # Initialize first frame if stack empty (fallback if not done at creation)
#     if not sem.frames:
#         func = get_function_by_addr(proj, cfg, cur_addr)
#         if func is None:
#             return
#         fname = func.name
#         if func.is_plt:
#             fname += " (PLT Stub)"
#         sem.frames.append(
#             Frame(
#                 sp=sp,
#                 callee=func.addr,
#                 callee_name=fname,
#                 caller=None,
#                 caller_name="",
#                 ret=None,
#                 func=func.addr,
#                 simproc=None,
#             )
#         )
#         print(f"[init fallback] {fname} @ 0x{cur_addr:x}, SP={f'0x{sp:x}' if sp is not None else 'None'}")
#         return

#     # Handle first IRSB when recent_bbl_addrs is empty or too short
#     if len(state.history.recent_bbl_addrs) < 2:
#         # First transition after state creation, prev_ins = current function start
#         func = get_function_by_addr(proj, cfg, cur_addr)
#         if func is not None:
#             prev_ins = func.addr
#         else:
#             # Can't determine previous instruction, skip this transition
#             return
#     else:
#         # recent_bbl_addrs[-2] = previous basic block (since [-1] is current block)
#         prev_ins = state.history.recent_bbl_addrs[-2]

#     name = get_function_name(proj, cfg, cur_addr, simproc=state.inspect.simprocedure is not None) or f"sub_{cur_addr:x}"
#     print(f"IRSB hook {name} @ 0x{cur_addr:x}, SP={f'0x{sp:x}' if sp is not None else 'None'}")

#     _update_frames_on_transition(sem, proj, cfg, prev_ins, cur_addr, sp)


# # ---------- Simple helper to attach CFG ----------

# def semantic_callstack_reconstruction(simgr: angr.SimulationManager, cfg):
#     """Attach CFG to existing states and initialize first frame if needed."""
#     for st in simgr.active + simgr.deadended + simgr.unconstrained:
#         if not st.has_plugin("sem_stack"):
#             st.register_plugin("sem_stack", SemanticCallstack())
#         st.sem_stack.cfg = cfg
        # Initialize first frame if not already done
        # _initialize_first_frame(st)


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