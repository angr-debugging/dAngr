l '/workspaces/dAngr/examples/cscbe/Apple_Pie'

input_len = 0x25

flag_chars = []
for i in range(input_len):
    char_sym = add_symbol ('flag_' + (to_str i)) 1
    append flag_chars char_sym

to_symbol flag (append flag_chars '\n')


ses 0x40c430 stdin=&sym.flag




breakpoint (by_address 0x40c521)
breakpoint (by_address 0x40c5fa)


exclude (by_address 0x407980)


exaf (fa 0x409cad)
exaf (fa 0x40a3e0)
exaf (fa 0x40afaf)
exaf (fa 0x40afa4)

run



sac &mem[(mg &reg.rsp+0x100 8 LE)->0x27] == &mem[0x47f6bc->0x27]
ev &sym.flag
 