# mbrainfuzz

In this challenge the contestants get a service that gives them a binary. The binary expects a password as argument. 
That password is then stored in memory and will be checked per 4 bytes in a function. Since the password is different for every binary we will have to use dAngr to automatically provide the argument.


# loading the binary

The first step is also loading the binary. Since this challenge is somewhat difficult we are going to split some functionality into functions. 
The address of the first function is going to be different for each binary, but the structure of the binary is the same. 




```
load '/workspaces/dAngr/examples/angr_examples/repo/angr_examples/examples/secuinside2016mbrainfuzz/sample_1'


def dict_to_list(dict):
    list = []
    for item in dict:
        append list item
    return list


def get_target_addr(function, target_offset):
    blocks_sorted = sort (dict_to_list &(&vars.function.block_addrs))
    target = blocks_sorted[target_offset]
    
    return target
```

```
def get_storage_address():
    block = bb
    instructions = &vars.block.assembly.insns
    n_inst = len instructions

    prev_addr = 0
    inst_ref = "eax, byte ptr [rip + "
    mem_addresses = []
    for i in range(n_inst-1, -1, -1):
        inst_str = &vars.instructions[i].insn.op_str
        if  inst_ref in inst_str:
            offset = to_int !(&vars.inst_str.replace(&vars.inst_ref, '').replace(']', ''))
            append mem_addresses (to_int (offset + prev_addr))
        
        prev_addr = &vars.instructions[i].address
    return mem_addresses

def get_func_inputs(func_addr, break_addr, avoid_addr, bytes):
    print "Getting the inputs from the function with addr"
    println (to_hex func_addr)
    print "excluding address"
    println (to_hex avoid_addr)

    set_blank_state addr=func_addr
    breakpoint (by_address break_addr)
    exclude (by_address avoid_addr)
    
    add_symbol arg1 1
    add_symbol arg2 1
    add_symbol arg3 1
    add_symbol arg4 1

    set_register rdi &sym.arg1
    set_register rsi &sym.arg2
    set_register rdx &sym.arg3
    set_register rcx &sym.arg4

    run

    block_2 = bb
    possition = &vars.block_2.address
    if possition != break_addr:
        println "Did not break where we had to"
        exit
    
    bytes[addresses[0]] = evaluate &sym.arg1
    bytes[addresses[1]] = evaluate &sym.arg2
    bytes[addresses[2]] = evaluate &sym.arg3
    bytes[addresses[3]] = evaluate &sym.arg4

    addresses = get_storage_address
    return bytes


```

```
start_function = get_function_info 'main'
target = get_target_addr start_function (-4)

set_blank_state addr=target
addresses = get_storage_address


print "First function at: "
println (to_hex target)


exploit = {}
func_addr = 0

while True:
    target_func = get_function_info target
    func_addr = &vars.target_func.addr

    blocks_sorted = sort (dict_to_list &(&vars.target_func.block_addrs))
    
    if 3 > (len blocks_sorted):
        print "found the end"
        break

    println !(len(&vars.exploit.keys( )))
    
    target = blocks_sorted[-2]
    to_exclude = blocks_sorted[-1]
    exploit = get_func_inputs func_addr target to_exclude exploit
    

exploit_str = ""
sorted_keys = !(sorted(&vars.exploit))
max_addr = !(max(&vars.sorted_keys))
min_addr = !(min(&vars.sorted_keys))
for key in range(min_addr, max_addr +1, 1):
    if key in exploit:
        hex_v = (to_hex exploit[key])
        exploit_str = exploit_str + (to_str hex_v)
    else:
        exploit_str = exploit_str + '00'


clear_breakpoints
set_entry_state args=["file", exploit_str] argc=2
breakpoint (by_address 0x4041ea)
run

```





func = get_function_info main
blocks_sorted = sort (dict_to_list &(&vars.func.block_addrs))
# Hier moeten we nr 4 hebben

# daarna telkens voorlaatste


```



set_blank_state addr=0x4007fc
breakpoint (by_address 0x40086a)
run
get_storage_address
```