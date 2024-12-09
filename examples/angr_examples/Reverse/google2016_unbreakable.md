load 'repo/angr_examples/examples/google2016_unbreakable_0/unbreakable-enterprise-product-activation'

add_symbol arg1 0x43

set_entry_state 0x400590   args=["file", &sym.arg1] argc=2
chopped_arg = chop_symbol &sym.arg1 8

add_constraint chopped_arg[0] == "C"
add_constraint chopped_arg[1] == "T"
add_constraint chopped_arg[2] == "F"
add_constraint chopped_arg[3] == "{"


breakpoint (by_stream "Thank you")
run

to_str (evaluate &sym.arg1)