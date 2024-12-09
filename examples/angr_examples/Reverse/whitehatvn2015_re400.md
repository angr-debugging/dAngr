# Nog niet af


def patch_0():
    x = 0

load 'repo/angr_examples/examples/whitehatvn2015_re400/re400.exe'
add_symbol arg1 37
set_entry_state 0x401f30 args=["file", &sym.arg1] argc=2

hook_region patch_0 0x401f7e 2399
hook_region patch_0 0x402b5d 52


arg_chars = (chop_symbol &sym.arg1 8)

for i in range(36):
    add_constraint arg_chars[i] > 0x20
    add_constraint arg_chars[i] > 0x7e

add_constraint arg_chars[-1] == 0



breakpoint (by_address 0x402f29)
exclude (by_address 0x402f3f)

run

