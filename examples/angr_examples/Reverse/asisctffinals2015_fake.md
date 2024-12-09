load 'repo/angr_examples/examples/asisctffinals2015_fake/fake'
 
add_symbol input 8
set_blank_state 0x4004ac
&reg.rax = &sym.input
breakpoint (by_address 0x400684)
run
run

flag = get_memory &reg.rsp 40

flag_arr = chop_symbol flag 8
 
 
add_constraint flag_arr[0] == "A"
add_constraint flag_arr[2] == "I"
add_constraint flag_arr[1] == "S"
add_constraint flag_arr[3] == "S"
add_constraint flag_arr[4] == "{"
add_constraint flag_arr[37] == "}"




for i in range(5,5+32, 1):
    cond_a = flag_arr[i] >= '0' && flag_arr[i] <= '9'
    cond_b = flag_arr[i] >= 'a' && flag_arr[i] <= 'f'
    add_constraint cond_a | cond_b


evaluate flag


