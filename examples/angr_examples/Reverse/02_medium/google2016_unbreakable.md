# Google 2016 unbreakable
```
load 'google2016_unbreakable'

add_symbol arg1 0x43

set_entry_state 0x400590   args=["file", &sym.arg1] argc=2
chopped_arg = chop_symbol &sym.arg1 8

add_constraint chopped_arg[0] == "C"
add_constraint chopped_arg[2] == "F"
add_constraint chopped_arg[1] == "T"
add_constraint chopped_arg[3] == "{"


breakpoint (by_stream "Thank you")
run


flag = (to_str (evaluate &sym.arg1))
println flag
println !(&vars.flag[:51])
```