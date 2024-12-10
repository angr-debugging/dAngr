# Ekoparty ctf 2015 rev_100

load 'repo/angr_examples/examples/ekopartyctf2015_rev100/counter'

add_symbol flag 32
set_entry_state args=["file", &sym.flag] argc=2 add_options=options.unicorn 

chopped = chop_symbol &sym.flag 8

for sym in chopped:
    add_constraint (sym > 0x20 && sym < 0x7e)

run