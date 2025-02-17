load '/workspaces/dAngr/examples/HTB/main'

breakpoint (by_address 0x400dc0)
run

inp = get_stdin_variables
inp_0 = inp[0]
chars = chop_symbol inp_0 8
add_constraint chars[3] == '{'

dump_stdstream stdin
