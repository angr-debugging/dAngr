import asyncio
import base64
from enum import Enum
from functools import singledispatch, singledispatchmethod
import os
from typing import Any, Callable, Coroutine, List

import angr
from pydantic import BaseModel


from dAngr.angr_ext.debugger import Debugger
from dAngr.angr_ext.step_handler import StepHandler, StopReason
from dAngr.angr_ext.filters import AddressFilter, SourceFilter
from dAngr.angr_ext.execution_context import ExecutionContext
from dAngr.angr_ext.utils import DataType
from dAngr.dap import dap_models as dap
from dAngr.dap.common import LaunchRequest
from dAngr.dap.dap_connection import DAPConnection, DAPConnection
from dAngr.exceptions import CommandError

from dAngr import exceptions as ex
from dAngr.utils import utils, get_logger

log = get_logger(__name__)

DebugState = Enum('DebugState',['Initializing','Configured'])

class InvalidStateError(Exception):
    """Base for command execution errors."""
    pass

class DAPDebugger(Debugger, StepHandler):
    def __init__(self,c:DAPConnection) -> None:
        super(DAPDebugger,self).__init__(c)
        self.conn:DAPConnection = c
        self.dap_breakpoints:List[dap.Breakpoint] = []
        self._breakpoints_set = False
        self._breakpoint_id = 0

        self._condition:asyncio.Condition = asyncio.Condition()
        self._state = DebugState.Initializing
        self.context:ExecutionContext = ExecutionContext(self)


    # def get_state_id(self):
    #     if self.current_state:
    #         return self.current_state.addr
    #     return 0
    
    async def _setState(self, s:DebugState):
        async with self._condition:
            self._state = s
            self._condition.notify_all()

    async def _waitForState(self, s: DebugState, timeout: float = 1000):
        async with self._condition:            
            try:
                await self._condition.wait_for(lambda: self._state == s)
                return True  # State reached within timeout
            except asyncio.TimeoutError:
                return False  # Timeout occurred before the state was reached
            
    async def set_inst_breakpoints(self, breakpoints:List[dap.InstructionBreakpoint]|None):
        lst = []
        if not breakpoints:
            breakpoints = []

        #remove breakpoints for same address
        remove = [bp for bp in self.dap_breakpoints if bp.instructionReference in [b.instructionReference for b in breakpoints]]
        for b in remove:
            await self.conn.send_event(dap.BreakpointEvent, body=dap.Body7(reason="remove", breakpoint= b))
        self.dap_breakpoints = [bp for bp in self.dap_breakpoints if bp.instructionReference not in [b.instructionReference for b in breakpoints]]
        #add new breakpoints
        for breakpoint in breakpoints:
            # self.breakpoints.append(AddressFilter(int(breakpoint.instructionReference))
            lst.append(dap.Breakpoint(
                id=self._breakpoint_id,
                verified=False,
                instructionReference=breakpoint.instructionReference
            )) # type: ignore
            self.dap_breakpoints.append(lst[-1])
            self._breakpoint_id += 1
        self._breakpoints_set = False
        await self.check_breakpoints()
        return lst


    async def set_breakpoints(self, source:dap.Source, breakpoints:List[dap.SourceBreakpoint]|None):
        lst = []
        self._breakpoints_set = False
        if not breakpoints:
            breakpoints = []
        if not source.path:
            log.error("No source found")
            return
        #remove breakpoints for source
        remove = [bp for bp in self.dap_breakpoints if bp.source and bp.source.path == source.path]
        for b in remove:
            await self.conn.send_event(dap.BreakpointEvent, body=dap.Body7(reason="remove", breakpoint= b))

        self.dap_breakpoints = [bp for bp in self.dap_breakpoints if bp.source and bp.source.path != source.path]
        #add new breakpoints
        for breakpoint in breakpoints:
            lst.append(dap.Breakpoint(
                id = self._breakpoint_id,
                verified=False,
                source = source,
                line = breakpoint.line,
                column = breakpoint.column)) # type: ignore
            self._breakpoint_id += 1
            self.dap_breakpoints.append(lst[-1])
        await self.check_breakpoints()
        return lst

    async def check_src_bp(self, bp:dap.Breakpoint):
        bp.reason = None
        bp.message = None
        if bp.verified:
            # breakpoint already verified
            return None
        if bp.source and bp.source.path and bp.line:
            addr = self.find_address(bp.source.path, bp.line)
            if addr == None:
                log.error("No address found for breakpoint at {bp.source.path}:{bp.line}")
                bp.reason = dap.Reason2.failed
                bp.message = "No address found for breakpoint at {bp.source.path}:{bp.line}"
                return None
            else:
                bp.verified = True
                return SourceFilter(addr, bp.source.path, bp.line)
            
        elif bp.instructionReference and bp.instructionReference.isnumeric():
            addr = int(bp.instructionReference,0)
            if addr:
                bp.verified = True
                return AddressFilter(addr)
            else:
                log.error("Invalid address for breakpoint")
                bp.reason = dap.Reason2.failed
                bp.message = "Invalid address for breakpoint"

                return None
        else:
            log.error("Invalid breakpoint")
            bp.reason = dap.Reason2.failed
            bp.message = "Invalid breakpoint"
            return None

    async def check_breakpoints(self):
        if not self._breakpoints_set:
            for bp in self.dap_breakpoints:
                if b:= await self.check_src_bp(bp):
                    self.breakpoints.append(b) # type: ignore
                else:
                    await self.conn.send_event(dap.BreakpointEvent, body=dap.Body7(reason="updated",breakpoint= bp))

                # elif b:= await self.checkSourceBp(bp):
                #     self.dap_breakpoints.append(b)
                #     self.breakpoints.append(SourceFilter(int(bp.instructionReference),bp.source.path, bp.line)) # type: ignore

            # self.dap_breakpoints = [b for b in self.dap_breakpoints if b.verified]
            # for bp in self.dap_breakpoints:
            #     #options:
            #     dap.Breakpoint
            #     dap.SourceBreakpoint
            #     dap.DataBreakpoint
            #     dap.FunctionBreakpoint
            #     dap.InstructionBreakpoint #Address filter
            #     dap.ExceptionBreakpointsFilter

            #     self.breakpoints.append(b)


    # def get_path(self,name):
    #     if not self._breakpoints_set:
    #         return next((b.source.path for b in self._breakpoints if b.source.name == name),None)
    #     else:
    #         return None
    
    # async def handle_exit(self):
    #     await self.conn.send_event(dap.TerminatedEvent)

    def handle_output(self, output:str):
        self.conn.send_output(output)

    def handle_step(self, reason:StopReason, state:angr.SimState|None):
        if reason == StopReason.TERMINATE:
            self.conn.send_event_sync(dap.TerminatedEvent) # type: ignore[call-arg]
            if not self.active:
                self.conn.send_event_sync(dap.ExitedEvent) # type: ignore[call-arg]
        elif state is None:
            self.conn.send_event_sync(dap.StoppedEvent, body=dap.Body1(reason='unknown', description='Stopped for unknown reaon',threadId=0, allThreadsStopped=True)) # type: ignore[call-arg]
        elif reason == StopReason.STEP:
            self.conn.send_event_sync(dap.StoppedEvent, body=dap.Body1(reason='step',  description="Stepped to next instruction", threadId=0, allThreadsStopped=True)) # type: ignore[call-arg]
        elif reason == StopReason.BREAKPOINT:
            ids=[]
            id=0
            for f in self.breakpoints.filters:
                if f.filter(state, self._single_step):
                    ids.append(id)
                id+=1
            self.conn.send_event_sync(dap.StoppedEvent, body=dap.Body1(reason='breakpoint', hitBreakpointIds=ids, description=f"Stopped at breakpoint {f}", threadId=0, allThreadsStopped=True)) # type: ignore[call-arg]
        else:
            self.conn.send_warning(f"Stopped for unknown reason at: {hex(start)}.") # type: ignore


    # async def handle_breakpoint(self,breakpoints:list[int]):
    #     ids = [bp.id for bp in self.dap_breakpoints if bp.instructionReference and int(bp.instructionReference) in breakpoints]
    #     threadId = self.get_state_id()
    #     await self.conn.send_event(dap.StoppedEvent, body=dap.Body1(reason="breakpoint",threadId=threadId, allThreadsStopped=True, hitBreakpointIds=ids)) # type: ignore[call-arg]
    
    # async def handle_pause(self, addr):
    #     await self.conn.send_event(dap.StoppedEvent, body=dap.Body1(reason='pause',threadId=self.get_state_id(addr), allThreadsStopped=True)) # type: ignore[call-arg]

    # async def handle_step(self,addr):
    #     await self.conn.send_event(dap.StoppedEvent, body=dap.Body1(reason="step",threadId=self.get_state_id(addr),allThreadsStopped=True)) # type: ignore[call-arg]

    async def run(self, until:Callable[[angr.SimulationManager],StopReason] = lambda _:StopReason.NONE):
        await self.check_breakpoints()
        prev_path, prev_line =self.get_source_info(self.current_state.addr)
        #if source code debugging
        def until_source(simgr):
            nonlocal prev_line, prev_path
            #if not at a source code line, proceed
            if simgr.one_active:
                path,line = self.get_source_info(simgr.one_active.addr)
                if not path and not line:
                    return StopReason.NONE
                elif path == prev_path and line == prev_line:
                    return StopReason.NONE
                else:
                    prev_path = path
                    prev_line = line
            return until(simgr)
        self._run(self,check_until=until_source,single_step=True)
        #TODO; support assembly level debugging
            
    async def handle_request(self,request:dap.Request):
        try:
            await self._handle_request(request)
        except CommandError as ex:
            await self.conn.send_req_error(ex,request)

    # Base handler - called if no type-specific handler is found
    @singledispatchmethod
    async def _handle_request(self,request:dap.Request):
        raise NotImplementedError(f"No handler implemented for type {request.command}")

    # Handler for InitializeRequest
    @_handle_request.register
    async def _(self, request: dap.InitializeRequest):
        await self._setState(DebugState.Initializing)
        await self.conn.send_response(dap.InitializeResponse,request,body=dap.Capabilities(
            supportsTerminateRequest = True,
#            supportsRestartRequest = True,
            supportsLoadedSourcesRequest = False,
            supportsSingleThreadExecutionRequests=True,
            supportsConfigurationDoneRequest = True,
            supportsReadMemoryRequest= True,
            supportsWriteMemoryRequest=True,
            supportsDisassembleRequest=True,
            supportsSteppingGranularity=True,
            supportsInstructionBreakpoints=True,
            supportsSetVariable=True,
        )) # type: ignore
        await self.conn.send_event(dap.InitializedEvent)

    @_handle_request.register
    async def _(self, request: dap.ConfigurationDoneRequest):
        await self._setState(DebugState.Configured)
        await self.conn.send_response(dap.ConfigurationDoneResponse,request)

    # Handler for LaunchRequest
    @_handle_request.register
    async def _(self, request: LaunchRequest):
        if not request.arguments.program: # type:ignore
            raise ex.InvalidArgumentError("No progran name found")
        if request.arguments.cwd: # type:ignore
            os.chdir(request.arguments.cwd) # type:ignore
        
        from_src = getattr(request.arguments, 'substitute_from', None)
        to_src = getattr(request.arguments, "substitute_to" , None)
        self.unconstrained_fill(False)
        self.init(request.arguments.program, args=request.arguments.args, from_src_path=from_src, to_src_path=to_src) # type:ignore
        self.project.analyses.CompleteCallingConventions(recover_variables=True, low_priority=False)
        if not await self._waitForState(DebugState.Configured):
            raise ex.InvalidArgumentError("Not properly configured")

        await self.conn.send_response(dap.LaunchResponse,request)
        if getattr(request.arguments,"stopOnEntry", False): 
            pass
        else:
            await self.run()

    @_handle_request.register
    async def _(self, request: dap.ContinueRequest):
        await self.conn.send_response(dap.ContinueResponse,request, body=dap.Body25(allThreadsContinued=True))
        await self.conn.send_event(dap.ContinuedEvent)
        await self.run()


    @_handle_request.register
    async def _(self, request: dap.RestartRequest):
        self.reset_state()
        await self.conn.send_response(dap.RestartResponse,request)
        await self.run()

    @_handle_request.register
    async def _(self, request: dap.TerminateRequest):
        self.stop()
        await self.conn.send_response(dap.TerminateResponse,request)
        await self.conn.send_event(dap.TerminatedEvent)


    @_handle_request.register
    async def _(self, request: dap.DisconnectRequest):
        self.stop()
        await self.conn.send_response(dap.DisconnectResponse,request)
        await self.conn.send_event(dap.ExitedEvent)
        await self.conn.disconnect()

    @_handle_request.register
    async def _(self, request: dap.ExitedEvent):
        await self.conn.disconnect()

    #TODO: currnetly only one thread
    @_handle_request.register
    async def _(self, request: dap.ThreadsRequest):
        threads = []
        threads.append(dap.Thread(id=0,name=f"Thread-{0}"))
        await self.conn.send_response(dap.ThreadsResponse, request, body = dap.Body31(threads=threads))


    @_handle_request.register
    async def _(self, request: dap.StackTraceRequest):
        id = request.arguments.threadId
        #assume active states are still the same
        stack = self.get_callstack(self.current_state)
        frames:List[dap.StackFrame] = []
        for s in stack:
            if not frames:
                path,line = self.get_source_info(self.current_state.addr)
            else:
                path,line = self.get_source_info(s["addr"]) # function address
            # _,endline = self.get_source_info(s["end"])
            if path:
                src = dap.Source(name=os.path.basename(path), path=path) # type: ignore
            else:
                src = None
            frames.append(
                dap.StackFrame(id=s['id'],name=s['name'],source=src, column=0, instructionPointerReference=f"{s['addr']}",
                               line=line) # type: ignore
            )
        frames.pop()

        await self.conn.send_response(dap.StackTraceResponse, request, body = dap.Body26(stackFrames=frames)) # type: ignore

    @_handle_request.register
    async def _(self, request: dap.SourceRequest):
        content = ""
        if source := getattr(request.arguments.source, 'path', None):
            content = utils.readfile(source)
        await self.conn.send_response(dap.SourceResponse, request, body = dap.Body30(content = content))

    @_handle_request.register
    async def _(self, request: dap.ScopesRequest):
        cs = self.get_callstack(self.current_state)
        
        if request.arguments.frameId >= len(cs):
            raise ex.DebuggerCommandError("Failed to handle scopes request, invalid frame")
        frameid = request.arguments.frameId
        frame = cs[frameid]
        func = self.get_function_info(frame['addr'])
        if not func:
            raise ex.DebuggerCommandError("Failed to handle scopes request, invalid function")
        path,line = self.get_source_info(func.addr)
        if not path:
            raise ex.DebuggerCommandError("Failed to handle scopes request, invalid source")
        src = os.path.basename(path)
        _, endline = self.get_source_info(max([b.addr for b in func.blocks]))
        scopes = []
        scopes.append(dap.Scope(name="Arguments", variablesReference=frameid*10+1, expensive=False, source=dap.Source(name=src,path=path),line=line,endLine=endline)) # type: ignore
        scopes.append(dap.Scope(name="Locals",    variablesReference=frameid*10+2, expensive=False, source=dap.Source(name=src,path=path),line=line,endLine=endline)) # type: ignore
        scopes.append(dap.Scope(name="Registers", variablesReference=frameid*10+3, expensive=True)) # type: ignore
        await self.conn.send_response(dap.ScopesResponse, request, body = dap.Body27(scopes=scopes))
        

    @_handle_request.register
    async def _(self, request: dap.NextRequest):
        # Step Over
        cs0 = self.get_callstack(self.current_state)
        def check_call_stack(simgr)->StopReason:
            cs = self.get_callstack(simgr.one_active)
            if len(cs)> len(cs0):
                return StopReason.NONE
            for i in range(len(cs),0):
                if cs[i]['func']!= cs0[i]['func']:
                    return StopReason.NONE
            return StopReason.STEP
        await self.run(check_call_stack) # return immediately
        await self.conn.send_response(dap.NextResponse, request)
   
    @_handle_request.register
    async def _(self, request: dap.StepInRequest):
        await self.run(lambda _: StopReason.STEP) # return immediately
        await self.conn.send_response(dap.StepInResponse, request)
    

    @_handle_request.register
    async def _(self, request: dap.StepOutRequest):
        cs0 = self.get_callstack(self.current_state)
        def check_call_stack(simgr)->StopReason:
            cs = self.get_callstack(simgr.one_active)
            if len(cs) < len(cs0):
                return StopReason.STEP
            return StopReason.NONE

        await self.run(check_call_stack) # return immediately
        await self.conn.send_response(dap.StepOutResponse, request)

    # PauseRequest - break running
    # @_handle_request.register
    # async def _(self, request: dap.PauseRequest):
    #     await self.pause()
    #     await self.conn.send_response(dap.PauseResponse,request)

    # @_handle_request.register
    # async def _(self, request: dap.WriteMemoryRequest):
    #     address = int(request.arguments.memoryReference,0) + request.arguments.offset
    #     data = base64.b64decode(request.arguments.data)
    #     await self.set_memory(address,data)
    #     await self.conn.send_response(dap.WriteMemoryResponse,request)

    # @_handle_request.register
    # async def _(self, request: dap.ReadMemoryRequest):
    #     address = int(request.arguments.memoryReference,0) + request.arguments.offset
    #     size = request.arguments.count
    #     data = await self.get_memory(address,size)
    #     await self.conn.send_response(dap.ReadMemoryResponse,request,body=dap.Body40(address,data=data))

    def convert_to_ctype(self, value, ctype):
        if ctype == 'int':
            return int(value)
        elif ctype == 'char':
            return chr(value)
        elif ctype == 'short':
            return int(value)
        elif ctype == 'long':
            return int(value)
        elif ctype == 'float':
            return float(value)
        elif ctype == 'double':
            return float(value)
        elif ctype == 'unsigned int':
            return int(value)
        elif ctype == 'unsigned char':
            return chr(value)
        elif ctype == 'unsigned short':
            return int(value)
        elif ctype == 'unsigned long':
            return int(value)
        elif ctype == 'unsigned long long':
            return int(value)
        elif ctype == 'long long':
            return int(value)
        elif ctype == 'long double':
            return float(value)
        elif ctype == 'char *':
            return hex(int(value))
        elif ctype == 'void':
            return None
        else:
            return value
    @_handle_request.register
    async def _(self, request: dap.VariablesRequest):
        r = request.arguments.variablesReference
        frameid = r // 10
        vars = []
        cs = self.get_callstack(self.current_state)[frameid]
        func = self.get_function_info(cs['func'])
        
        if not func:
            pass
        elif r % 10 == 1: # arguments
            args = self.get_args(func)
            print(self._state)
            if not func.calling_convention:
                pass
            elif args_v:=func.calling_convention.get_args(self.current_state, func.prototype):
                i=0
                for arg in args_v:
                    #evaluate arg
                    tp = DataType.bytes if not args[i]['type'].endswith("*") and not args[i]['type'] =="int" else DataType.int
                    value =  self.eval_symbol(arg.get_value(self.current_state), tp)
                    # convert to type
                    value = self.convert_to_ctype(value, args[i]['type'])
                    name = args[i]['name']
                    vars.append(dap.Variable(variablesReference=frameid, name=name,value=str(value),type=args[i]['type']))
                    i+=1
        elif r % 10 == 2: # locals
            locals = self.get_variables(func)
            i=0
            for local in locals:
                try:
                    # get local var value
                    name = local['name']
                    value = self.project.kb.dvars._dvar_containers[name].from_pc(self.current_state.addr+self._base_addr)
                    if not value:
                        continue
                    # convert to type
                    # value = self.convert_to_ctype(value, local['type'])
                    value=str(value)
                    vars.append(dap.Variable(variablesReference=frameid,name=name,value=str(value),type=local['type'])) # type: ignore
                    i+=1
                except Exception as e:
                    log.error(f"Error getting local variable {local['name']}: {e}")
                    pass
        else:  # registers
            regs = self.list_registers()
            for n in regs:
                vars.append(dap.Variable(variablesReference=frameid,name=n,value=str(self.get_register_value(regs[n])),type="int")) # type: ignore
            pass
        await self.conn.send_response(dap.VariablesResponse,request,body=dap.Body28(variables=vars))

    # @_handle_request.register
    # async def _(self, request: dap.SetVariableRequest):
    #     varRef = request.arguments.variablesReference
    #     name = request.arguments.name
    #     value = request.arguments.value
    #     frameid = varRef // 10
    #     cs = self.get_callstack()[frameid]
    #     func = self.get_function_info(cs['func'])
    #     if varRef % 10 == 1:
    #         self.set_function_argument(func,cs.state,name,value)
    #     elif varRef % 10 == 2:
    #         self.set_variable(name, value, state=cs.state)
    #     else:
    #         # set register
    #         self.set_register(name, value, state=cs.state)

    #     await self.conn.send_response(dap.SetVariableResponse,request)


    @_handle_request.register
    async def _(self, request: dap.SetBreakpointsRequest):
        await self.set_breakpoints(request.arguments.source, request.arguments.breakpoints)
        await self.conn.send_response(dap.SetBreakpointsResponse,request,body=dap.Body19(breakpoints=self.dap_breakpoints))

    @_handle_request.register
    async def _(self, request: dap.SetInstructionBreakpointsRequest):
        new = await self.set_inst_breakpoints(request.arguments.breakpoints)
        await self.conn.send_response(dap.SetInstructionBreakpointsResponse,request,body=dap.Body24(breakpoints=new))

    @_handle_request.register
    async def _(self, request:dap.DisassembleRequest):
        """
        Handles a DAP DisassembleRequest using angr and returns a DisassembleResponse.
        
        :param proj: angr project
        :param request: DAP DisassembleRequest object
        :return: DAP DisassembleResponse object
        """
        memory_ref = int(request.arguments.memoryReference, 16)  # Address to disassemble
        offset = request.arguments.offset if request.arguments.offset else 0  # Optional offset
        count = request.arguments.instructionCount  # Number of instructions
        addr = memory_ref + offset  # Effective address

        # Get the basic block containing the address
        block = self.project.factory.block(addr, num_inst=count)

        # Initialize Capstone disassembler (angr uses Capstone under the hood)
        arch = self.project.arch
        cs = arch.capstone  # Capstone instance from angr
        instructions = list(cs.disasm(block.bytes, block.addr))

        # Convert disassembled instructions to DAP format
        instructions = [
            dap.DisassembledInstruction(
                address=hex(inst.address),
                instructionBytes=inst.bytes.hex(),
                instruction=inst.mnemonic + " " + inst.op_str
            ) # type: ignore
            for inst in instructions
        ]

        # Construct and return the response
        return self.conn.send_response(dap.DisassembleResponse,request, body = dap.Body42(instructions=instructions))

    # BreakpointLocationsRequest
    @_handle_request.register
    async def _(self, request: dap.BreakpointLocationsRequest):
        locs = []
        for bp in self.dap_breakpoints:
            if bp.line and bp.source and request.arguments and bp.source.path == request.arguments.source.path:
                locs.append(dap.BreakpointLocation(line=bp.line, column=None, endLine=bp.line, endColumn=None))
        await self.conn.send_response(dap.BreakpointLocationsResponse,request,body=dap.Body18(breakpoints=locs))

# EvaluateRequest
# ExceptionInfoRequest
# GotoRequest - skip code to run -- not yet
# GotoTargetsRequest -- not yet

# ModulesRequest
# StepInTargetsRequest
# ReverseContinueRequest
# StepBackRequest - step -1

# SetDataBreakpointsRequest
# SetExceptionBreakpointsRequest
# SetExpressionRequest
# SetFunctionBreakpointsArguments
# SetInstructionBreakpointsRequest
# SourceRequest
# LoadedSourcesRequest -- no


# DataBreakpointInfoRequest ?
#