# dAngr Documentation

This documentation contains all the commands available in the dAngr debugger.

## Debugger Commands

### execution:
* `continue`  (short: `c`)  
  Run until a breakpoint, a fork (if not fully concrete), or until execution completed.  

* `exit`  (short: `e`)  
  Exit the debugger.  

* `start_at_address`  (short: `saa`)  
  Start execution at selected entrypoint.  
  - arguments: start_address (int)  
  
  Example: `start_at_address <start_address>`  

* `load_hooks`  (short: `lh`)  
  Load a python file containing SimProcedures as hooks.  
  - arguments: filename (str)  
  
  Example: `load_hooks <filename>`  

* `load`  (short: `l`)  
  Setup the simulation manager with the initial state.  
  - arguments: binary_path (str)  
  
  Example: `load <binary_path>`  

* `pause`  (short: `p`)  
  Pause debugging.  

* `start`  (short: `s`)  
  Run until a breakpoint, a fork (if not fully concrete), or until execution completed.  

* `step`  (short: `s`)  
  Take a next debugging step.  

* `step_over`  (short: `so`)  
  Take a next debugging step.  

* `step_out`  (short: `so`)  
  Step out of current function.  

* `reload`  (short: `r`)  
  Reset the simulation manager to the initial state.  


### info:
* `get_cfg`  (short: `gc`)  
  Return the control flow graph in dot format.  

* `get_current_block`  (short: `gcb`)  
  Show the assembly for the current basic block.  

* `list_active_paths`  (short: `lap`)  
  List the active paths.  

* `list_constraints`  (short: `lc`)  
  List the current path's constraints and symbolic variables.  

* `list_binary_symbols`  (short: `lbs`)  
  List the debugsymbols when available.
     Requires DWARF info.  

* `list_path_history`  (short: `lph`)  
  Get the address of previously executed basic blocks.  


### breakpoints:
* `add_breakpoint_at_line`  (short: `abal`)  
  Set a breakpoint at an address corresponding to the 'filename' and 'line number' in the source code file
     Requires debug sumbols available in the binary.  
  - arguments: source_file (str), line_nr (int)  
  
  Example: `add_breakpoint_at_line <source_file>, <line_nr>`  

* `add_breakpoint`  (short: `ab`)  
  Set a breakpoint at a given address.  
  - arguments: address (int)  
  
  Example: `add_breakpoint <address>`  

* `disable_breakpoint_at_line`  (short: `dbal`)  
  Disable a breakpoint at the specified source file and line number.  
  - arguments: source_file (str), line_nr (int)  
  
  Example: `disable_breakpoint_at_line <source_file>, <line_nr>`  

* `disable_breakpoint`  (short: `db`)  
  Disable a breakpoint at the specified address.  
  - arguments: address (int)  
  
  Example: `disable_breakpoint <address>`  

* `enable_breakpoint_at_line`  (short: `ebal`)  
  Enable a breakpoint at the specified source file and line number.  
  - arguments: source_file (str), line_nr (int)  
  
  Example: `enable_breakpoint_at_line <source_file>, <line_nr>`  

* `enable_breakpoint`  (short: `eb`)  
  Enable a breakpoint at the specified address.  
  - arguments: address (int)  
  
  Example: `enable_breakpoint <address>`  

* `list_breakpoints`  (short: `lb`)  
  List all breakpoints.  

* `remove_breakpoint_at_line`  (short: `rbal`)  
  Remove a breakpoint at an address corresponding to the filename and line number of the source code
     Requires debug sumbols available in the binary.  
  - arguments: source_file (str), line_nr (int)  
  
  Example: `remove_breakpoint_at_line <source_file>, <line_nr>`  

* `remove_breakpoint`  (short: `rb`)  
  Remove a breakpoint at a specific address.  
  - arguments: address (int)  
  
  Example: `remove_breakpoint <address>`  

* `clear_breakpoints`  (short: `cb`)  
  Remove all breakpoints.  


### functions:
* `set_function_prototype`  (short: `sfp`)  
  Set the function prototype including name, argument types and return type.
     Example: void myfunc(char*, int)  
  - arguments: prototype (str)  
  
  Example: `set_function_prototype <prototype>`  

* `set_function_call`  (short: `sfc`)  
  Initialize the function based on the previously pased prototype with the arguments.
     Example: void myfunc("txt", 10)  
  - arguments: function_call (str)  
  
  Example: `set_function_call <function_call>`  

* `get_return_value`  (short: `grv`)  
  Get the return value after running the function.  


### memory:
* `get_int_memory`  (short: `gim`)  
  Get memory value as integer.  
  - arguments: address (int)  
  
  Example: `get_int_memory <address>`  

* `get_memory`  (short: `gm`)  
  Get memory value of lengt size at a specific address as a byte array.  
  - arguments: address (int), size (int)  
  
  Example: `get_memory <address>, <size>`  

* `get_register`  (short: `gr`)  
  Get a register value.  
  - arguments: name (str)  
  
  Example: `get_register <name>`  

* `get_string_memory`  (short: `gsm`)  
  Get 0 delimited string starting at given memory address and convert it to str.  
  - arguments: address (int)  
  
  Example: `get_string_memory <address>`  

* `list_registers`  (short: `lr`)  
  List the registers and their current values  

* `set_memory`  (short: `sm`)  
  Set a memory value at a specific address.
    Supported Types: int, str, bytes.  
  - arguments: address (int), value (any)  
  
  Example: `set_memory <address>, <value>`  

* `set_register`  (short: `sr`)  
  Set a register value.  
  - arguments: name (str), value (int)  
  
  Example: `set_register <name>, <value>`  

* `zero_fill`  (short: `zf`)  
  Enable or disable to fill memory and registers with zero values.  
  - optional arguments: enable (bool)  


