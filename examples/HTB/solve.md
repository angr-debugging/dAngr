load '/workspaces/dAngr/examples/HTB/main2'

add_symbol flag 44

def pass():
    nop = 0

hook_region pass 0x40128b 5

breakpoint (by_address 0x401290)
run
(set_memory (&reg.rbp -0x8) &sym.flag)
breakpoint (by_stream "authorised")
run
