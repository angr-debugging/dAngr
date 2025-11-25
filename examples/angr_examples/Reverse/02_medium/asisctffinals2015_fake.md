
# ASIS ctf finals 2015 - fake

```
load 'asisctffinals2015_fake'
 
add_symbol input 8
set_blank_state addr=0x4004ac
&reg.rax = &sym.input
breakpoint (by_address 0x00400684)
run

flag = get_memory &reg.rdi 50

flag_arr = chop_symbol flag 8
 
 
add_constraint flag_arr[0] == "A"
add_constraint flag_arr[2] == "I"
add_constraint flag_arr[1] == "S"
add_constraint flag_arr[3] == "S"
add_constraint flag_arr[4] == "{"
add_constraint flag_arr[37] == "}"

for i in range(5,37):
    add_constraint flag_arr[i] < 0x7f && flag_arr[i] > 0x20

step
println (strip (evaluate (get_memory &reg.rdi 40)) b'\x00')
```

