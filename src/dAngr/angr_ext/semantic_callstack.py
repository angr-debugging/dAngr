from typing import TYPE_CHECKING
import angr
from angr.state_plugins import SimStatePlugin

from dAngr.angr_ext.utils import get_function_by_addr, is_plt_stub

from dAngr.utils.loggers import get_logger

if TYPE_CHECKING:
    from typing import cast
else:
    # Runtime no-op cast
    def cast(typ, val):
        return val

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
    Semantic callstack state plugin for angr states.
    
    This is a pure state plugin that maintains frame data only. It does NOT
    manage hook registration or frame update logic. That is delegated to
    SemanticCallStackHandler which operates on this plugin's data.
    
    This separation ensures:
    1. Frame data stays synchronized with the state it belongs to
    2. Hooks and frame updates are managed externally via the handler
    3. States can be copied cleanly without hook conflicts
    
    Attributes:
        frames:         list[Frame] – semantic callstack (bottom → top).
        cfg:            angr CFG instance (for frame name enrichment, can be None).
    """

    def __init__(self, cfg=None, frames=None):
        super().__init__()
        self.frames: list[Frame] = list(frames) if frames else []
        self.cfg = cfg

    def copy(self, memo):
        # Copy just the frame data, no hook re-registration
        new = SemanticCallstack.__new__(SemanticCallstack)
        SimStatePlugin.__init__(new)
        new.frames = list(self.frames)
        new.cfg = self.cfg
        return new
    
    # ========== Helper Methods ==========
    
    @staticmethod
    def _get_concrete_sp(state: angr.SimState) -> int | None:
        """Extract concrete stack pointer value from state."""
        try:
            sp = state.regs.sp
            if getattr(sp, "symbolic", False) is False:
                return getattr(sp, "concrete_value", None)
        except Exception:
            pass
        return None
    
    @staticmethod
    def _get_function_by_addr(proj: angr.Project, cfg: angr.analyses.cfg.CFG, addr: int):
        """Get function object from CFG or symbols."""
        if cfg is None:
            return get_function_by_addr(proj, addr)
        node = cfg.model.get_any_node(addr)
        if node and node.function_address:
            addr = node.function_address
        return get_function_by_addr(proj, addr)
    
    def _get_function_name(self, state: angr.SimState, addr: int, simproc: bool = False) -> str:
        """Get function name from CFG or generate address-based name."""
        proj: angr.Project = state.project # type: ignore
        
        if self.cfg is not None:
            func = self._get_function_by_addr(proj, self.cfg, addr)
            if func:
                name = func.name
                if simproc:
                    return f"{name} [SimProc]"
                elif is_plt_stub(proj, func.addr):
                    return f"{name} (PLT Stub)"
                return name
        
        return f"sub_{addr:x}"
    
    def _get_return_address(self, state: angr.SimState, callee_addr: int) -> int | None:
        """Try to find return address from CFG call site analysis."""
        if self.cfg is None or not self.frames:
            return None
        
        proj: angr.Project = state.project # type: ignore
        top = self.frames[-1]
        func = self._get_function_by_addr(proj, self.cfg, top.func)
        
        if func:
            call_sites = func.get_call_sites()
            for cs in call_sites:
                target = func.get_call_target(cs)
                if target == callee_addr:
                    return func.get_call_return(cs)
        
        return None
    
    # ========== Frame Management ==========
    
    def initialize_first_frame(self, state: angr.SimState):
        """Initialize the first frame at state creation to capture _start or entry point."""
        if self.frames:
            # Already initialized
            return
        
        sp = self._get_concrete_sp(state)
        cur_addr = state.addr
        fname = self._get_function_name(state, cur_addr)
        
        self.frames.append(
            Frame(
                sp=sp,
                callee=cur_addr,
                callee_name=fname,
                caller=None,
                caller_name="",
                ret=None,
                func=cur_addr,
                simproc=None,
            )
        )
        log.debug(f"[init first frame] {fname} @ 0x{cur_addr:x}, SP={f'0x{sp:x}' if sp is not None else 'None'}")
    
    def handle_call(self, state: angr.SimState):
        """Handle a function call - create new frame."""
        simproc = getattr(state.inspect, 'simprocedure', None)
        name = self._get_function_name(state, state.addr, simproc=simproc is not None)
        ret_addr = self._get_return_address(state, state.addr)
        
        # Push new frame to stack
        top = self.frames[-1] if self.frames else None
        caller_addr = top.func if top else None
        caller_name = top.callee_name if top else ""
        
        self.frames.append(
            Frame(
                sp=self._get_concrete_sp(state) or 0,
                callee=state.addr,
                callee_name=name,
                caller=caller_addr,
                caller_name=caller_name,
                ret=ret_addr,
                func=state.addr,
                simproc=None,
            )
        )
    
    def handle_return(self, state: angr.SimState):
        """Handle a function return - pop frame."""
        if self.frames:
            self.frames.pop()
    
    def handle_basic_block_start(self, state: angr.SimState):
        """Handle start of basic block - reset call flag (called by handler)."""
        pass  # Actual logic is in handler
    
    def handle_basic_block_end(self, state: angr.SimState, has_call: bool):
        """Handle end of basic block - detect tail calls.
        
        Args:
            state: The current state
            has_call: Whether a call occurred in this block
        """
        if not has_call and self.frames:
            # No call in this block -> must be a tail call
            simproc = getattr(state.inspect, 'simprocedure', None)
            callee_name = self._get_function_name(state, state.addr, simproc=simproc is not None)
            sp = self._get_concrete_sp(state) or 0
            
            if sp != self.frames[-1].sp:
                log.warning(f"Tail call with different SP (old=0x{self.frames[-1].sp:x} new=0x{sp:x})")
            
            # Replace top frame
            top = self.frames.pop()
            self.frames.append(
                Frame(
                    sp=top.sp,
                    callee=state.addr,
                    callee_name=callee_name,
                    caller=top.caller,
                    caller_name=top.caller_name,
                    ret=top.ret,
                    func=state.addr,
                    simproc=None,
                )
            )
    
    def restore_callstack_info(self, state: angr.SimState):
        """Restore/update frame information after CFG is generated.
        
        This method is called after CFG generation to update function names
        and addresses for frames that were created before CFG was available.
        It preserves the stack structure (SP values, return addresses) but
        enriches it with CFG-derived information.
        """
        if self.cfg is None:
            log.warning("Cannot restore callstack info: CFG is not available")
            return
        
        proj: angr.Project = state.project # type: ignore
        
        for frame in self.frames:
            # Update function information for the callee
            func = self._get_function_by_addr(proj, self.cfg, frame.callee)
            if func:
                frame.callee_name = func.name
                if is_plt_stub(proj, func.addr):
                    frame.callee_name += " (PLT Stub)"
            else:
                # Keep or set default name
                frame.callee_name = frame.callee_name or f"sub_{frame.callee:x}"
            
            # Update caller information if present
            if frame.caller is not None:
                caller_func = self._get_function_by_addr(proj, self.cfg, frame.caller)
                if caller_func:
                    frame.caller_name = caller_func.name
                else:
                    frame.caller_name = frame.caller_name or f"sub_{frame.caller:x}"
            
            # Try to find return address if missing (for frames created before CFG)
            if frame.ret is None and frame.caller is not None:
                caller_func = self._get_function_by_addr(proj, self.cfg, frame.caller)
                if caller_func:
                    call_sites = caller_func.get_call_sites()
                    for cs in call_sites:
                        target = caller_func.get_call_target(cs)
                        if target == frame.callee:
                            frame.ret = caller_func.get_call_return(cs)
                            break
        
        log.debug(f"Restored callstack info for {len(self.frames)} frames")
    
    def update_cfg(self, state: angr.SimState, cfg):
        """Update CFG and restore frame information if this is the first CFG.
        
        Args:
            state: The angr state
            cfg: The CFG instance
        """
        if cfg is None:
            return
        
        had_cfg = self.cfg is not None
        self.cfg = cfg
        
        # If we're adding CFG for the first time and frames already exist, restore their info
        if not had_cfg and self.frames:
            self.restore_callstack_info(state)
    
    def _log_stack(self, state: angr.SimState, location: str):
        """Debug logging for callstack state changes."""
        if self.cfg is None:
            return
        
        stack_ptr = self._get_concrete_sp(state)
        addr = state.addr
        proj: angr.Project = state.project # type: ignore
        
        if n := self.cfg.model.get_any_node(addr):
            func_addr = n.function_address
            func = self._get_function_by_addr(proj, self.cfg, func_addr)
            func_name = func.name if func and func.name else "unknown"
        else:
            func_addr = 0
            func_name = "unknown"
        
        simproc = getattr(state.inspect, 'simprocedure', None)
        if simproc is not None:
            func_name += f" [SimProc: {simproc.display_name}]"
        
        log.debug(f"{location} - State at 0x{addr:x} in function {func_name} (0x{func_addr:x}), SP={f'0x{stack_ptr:x}' if stack_ptr is not None else 'None'}")

    @staticmethod
    def _name():
        return "sem_stack"


# ========== SemanticCallStackHandler ==========

class SemanticCallStackHandler:
    """
    Handler for managing semantic callstack tracking across states.
    
    This handler separates concerns:
    - Manages hook registration and lifecycle
    - Updates frame data in the plugin based on execution events
    - Operates on the state's SemanticCallstack plugin instance
    - Ensures frames stay synchronized with actual execution
    
    Usage:
    
    1. Create handler and initialize tracking:
       >>> handler = SemanticCallStackHandler()
       >>> handler.initialize(state, cfg=None)
       >>> # Hooks are registered, first frame is created
    
    2. Handler calls methods on state's plugin:
       >>> # During stepping, handler hooks are triggered
       >>> # These call methods on state.sem_stack (the plugin)
    
    3. Update CFG when available:
       >>> handler.update_cfg(state, cfg)
       >>> # Enriches frame information with CFG data
    """
    
    def __init__(self):
        self.has_call = False  # Track whether a call occurred in current block
    
    def initialize(self, state: angr.SimState, cfg=None) -> SemanticCallstack:
        """Initialize semantic callstack tracking for a state.
        
        Args:
            state: The angr state to track
            cfg: The CFG instance (can be None initially)
            
        Returns:
            The SemanticCallstack plugin instance
        """
        if state.has_plugin("sem_stack"):
            # Already initialized, just update CFG if provided
            sem = cast(SemanticCallstack, state.sem_stack)
            if cfg is not None:
                self.update_cfg(state, cfg)
            return sem
        
        # Create and register new plugin
        sem = SemanticCallstack(cfg)
        state.register_plugin("sem_stack", sem)
        
        # Initialize first frame
        sem.initialize_first_frame(state)
        
        # Register hooks
        self.register_hooks(state)
        
        return sem
    
    def update_cfg(self, state: angr.SimState, cfg):
        """Update CFG for a state's callstack.
        
        Args:
            state: The angr state
            cfg: The CFG instance
        """
        if state.has_plugin("sem_stack"):
            sem = cast(SemanticCallstack, state.sem_stack)
            sem.update_cfg(state, cfg)
    
    def register_hooks(self, state: angr.SimState):
        """Register inspection breakpoints for tracking calls/returns/basic blocks."""
        state.inspect.b("irsb", when=angr.BP_AFTER, action=self._on_irsb_after)
        state.inspect.b("irsb", when=angr.BP_BEFORE, action=self._on_irsb_before)
        state.inspect.b("call", when=angr.BP_BEFORE, action=self._on_call)
        state.inspect.b("return", when=angr.BP_BEFORE, action=self._on_return)
    
    # ========== Hook Handlers ==========
    
    def _on_call(self, state: angr.SimState):
        """Hook handler: called before a function call instruction."""
        self.has_call = True
        if state.has_plugin("sem_stack"):
            sem = cast(SemanticCallstack, state.sem_stack)
            sem._log_stack(state, "+Call")
            sem.handle_call(state)
    
    def _on_return(self, state: angr.SimState):
        """Hook handler: called before a return instruction."""
        self.has_call = True
        if state.has_plugin("sem_stack"):
            sem = cast(SemanticCallstack, state.sem_stack)
            sem._log_stack(state, "+Return")
            sem.handle_return(state)
    
    def _on_irsb_before(self, state: angr.SimState):
        """Hook handler: called before executing a basic block."""
        self.has_call = False
        if state.has_plugin("sem_stack"):
            sem = cast(SemanticCallstack, state.sem_stack)
            sem._log_stack(state, "+IRSB")
    
    def _on_irsb_after(self, state: angr.SimState):
        """Hook handler: called after executing a basic block."""
        if state.has_plugin("sem_stack"):
            sem = cast(SemanticCallstack, state.sem_stack)
            sem._log_stack(state, "-IRSB")
            # Detect tail calls: if no call in this block, current instruction is a tail call
            sem.handle_basic_block_end(state, self.has_call)


# ========== Initialization ==========

def initialize_semantic_callstack(state: angr.SimState, cfg=None) -> SemanticCallstack:
    """Initialize semantic callstack tracking for a state.
    
    Convenience function that creates a handler and initializes tracking.
    
    Args:
        state: The angr state to track
        cfg: The CFG instance (can be None initially)
        
    Returns:
        The SemanticCallstack instance
    """
    handler = SemanticCallStackHandler()
    return handler.initialize(state, cfg)


# ========== Data Classes ==========

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