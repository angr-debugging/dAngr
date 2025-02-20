# 06_0cft_trace

In this challenge you get a state 
```
load '0ctf_trace.bin' backend='blob' base_addr=0x400770 arch='mipsel'
verbose_step False
set_blank_state addr=0x4009d4
add_symbol flag 32

set_memory 0x400D80 &sym.flag
set_memory 0x410EA0 0x400D80 endness=LE

res = []
delays = []
file = !(open("0ctf_trace.log"))
for line in file:
    if !(&vars.line.startswith("[INFO]")):
        addr = "0x" + line[6:6+8]
        append res addr

total = len res
```

```
def step_to_next_block():
    block = bb
    
    bb_size = &vars.block.instructions
    if bb_size > (len res):
        break
    target_step = to_int (res[bb_size])
    res = res[bb_size:]
    states = list_states
    state_found = 0
    state_count = len states
    selected_state_index = -1

    i = 0
    step
    while (state_found == 0):
        select_state i
        step_addr = &state.addr
        print "searching for state with the address: "
        println target_step
        println step_addr
        println (step_addr == target_step)
        if step_addr == target_step:
            state_found = 1
            selected_state_index = i
        
        i = i + 1

    for i in range(state_count):
        if i != selected_state_index:
            move_state_to_stash i active pruned

    return state_found
```

```
state_found = 1
while state_found:
    state_found = step_to_next_block
    println (total - (len res))

flag = to_str (evaluate &sym.flag)
println !(&vars.flag.replace("\x00", ""))
```



