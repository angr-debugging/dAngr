
# ASIS ctf finals 2015 - fake

```
load 'repo/angr_examples/examples/asisctffinals2015_fake/fake'
 
add_symbol input 8
set_blank_state addr=0x4004ac
&reg.rax = &sym.input
breakpoint (by_address 0x400684)
run



flag = get_memory &reg.rsp 40

flag_arr = chop_symbol flag 8
 
 
add_constraint flag_arr[0] == "A"
add_constraint flag_arr[2] == "I"
add_constraint flag_arr[1] == "S"
add_constraint flag_arr[3] == "S"
add_constraint flag_arr[4] == "{"
add_constraint flag_arr[37] == "}"


println (evaluate flag)

winning_nr = to_int &(evaluate &sym.input)

clear_breakpoints
set_blank_state addr=0x4004ac
&reg.rax = winning_nr

run
```

# ASIS{f5f7af556bd6973bd6f2687280a243d9}