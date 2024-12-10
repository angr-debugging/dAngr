# Flareon 2015  challenge 2

load 'repo/angr_examples/examples/flareon2015_2/very_success'


set_blank_state addr=0x401084

add_symbol password 0x32
set_entry_state stdin=&sym.password


breakpoint (by_stream "success")
run

password = strip (evaluate &sym.password) b'\x00'

println password