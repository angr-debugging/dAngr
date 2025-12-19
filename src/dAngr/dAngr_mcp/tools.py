from dAngr.cli.debugger_commands.base import BaseCommand


dAngr_tools = [
    "add_breakpoint",
    "add_breakpoint_at_function",
    "remove_breakpoint",
    "remove_breakpoint_at_function",
    #"enable_breakpoint",
    #"disable_breakpoint",
    "list_breakpoints",
    "clear_breakpoints",
    "add_exclusion",
    #"enable_exclusion",
    "list_exclusions",
    "clear_exclusions",
    "run",
    #"step_over", Currently broken
    "step",
    #"single_step",
    "load",
    "hook_function",
    "set_full_state",
    "set_blank_state",
    "get_current_state",
    "keep_unconstrained",
    "reset_state",
    "move_state_to_stash",
    "move_to_stash",
    #"undo_step",
    "dump_stdstream",
    "create_symbolic_file",
    "get_function_info",
    "decompiled_function_at_address",
    "decompiled_function",
    #"get_basicblocks", write own implementation
    "get_current_block",
    "get_basicblock_at",
    "get_stashes",
    "list_states",
    "list_binary_strings",
    "list_binary_symbols",
    "list_binary_sections",
    #"list_constraints",
    "list_path_history",
    #"init_callstack",
    #"get_callstack",
    "get_binary_info",
    #"get_binary_security_features",
    #"malloc",
    #"free",
    "unconstrained_fill",
    "list_registers",
    "get_register",
    "set_memory",
    #"get_stdin_variables",
    #"get_addr_for_name",
    "get_memory",
    "get_memory_string",
    "get_stack",
    "add_symbol",
    #"get_symbol",
    #"to_symbol",
    "is_symbolic",
    "remove_symbol"
]
 

class McpCommand(BaseCommand):
    __disable_autorender__ = True

    def __init__(self, debugger, mcp):
        super().__init__(debugger)
        self.mcp = mcp
        self._create_tools()

    def _get_class_functions(self):
        functions = []
        for function_name, function in type(self).__dict__.items():
            if function_name.startswith('_'):
                continue
            functions.append(function_name)
        
        return functions

    def _create_tools(self):
        functions = self._get_class_functions()
        for name in functions:
            self.mcp.tool()(getattr(self, name))
