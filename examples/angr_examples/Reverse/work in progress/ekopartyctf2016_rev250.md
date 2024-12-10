load 'repo/angr_examples/examples/ekopartyctf2016_rev250/FUck_binary'

start = 0x400B30
find = 0x403a40


for i in range(100):
    avoid_i = 0x403a7e + i * 60
    exclude (by_address avoid_i)


add_symbol flag 100
breakpoint (by_address 0x403a28)
exclude (by_stream "Goodbye!")

set_entry_state 0x400B30 stdin=&sym.flag

for sym in (chop_symbol &sym.flag 8):
    add_constraint sym <= 0x7e
    add_constraint sym >= 0x20

run

to_str (evaluate &sym.flag)