# Nog iets mis met dit voorbeeld

def patch_0():
    _ = 0

load 'repo/angr_examples/examples/whitehatvn2015_re400/re400.exe'

hook_region patch_0 0x401f7e 2399
hook_region patch_0 0x402b5d 52

add_symbol arg1 37

argv = ["re400.exe", &sym.arg1]
argc = 2

set_blank_state 0x401f30

arg_chars = (chop_symbol &sym.arg1 8)


add_constraint arg_chars[0] >= arg_chars[1]
add_constraint arg_chars[0] ^ arg_chars[1] == 0x1f
add_constraint arg_chars[4] <= arg_chars[5]
add_constraint arg_chars[4] ^ arg_chars[5] == 0x67
add_constraint arg_chars[8] >= arg_chars[9]
add_constraint arg_chars[8] ^ arg_chars[9] == 0x5a
add_constraint arg_chars[34] <= arg_chars[35]
add_constraint arg_chars[34] ^ arg_chars[35] == 0x8
add_constraint arg_chars[10] <= arg_chars[11]
add_constraint arg_chars[10] ^ arg_chars[11] == 0x6b
add_constraint arg_chars[6] >= arg_chars[7]
add_constraint arg_chars[6] ^ arg_chars[7] == 0xd
add_constraint arg_chars[2] <= arg_chars[3]
add_constraint arg_chars[2] ^ arg_chars[3] == 0x34
add_constraint arg_chars[32] >= arg_chars[33]
add_constraint arg_chars[32] ^ arg_chars[33] == 0x1e


for i in range(36):
    add_constraint arg_chars[i] >= 0x20
    add_constraint arg_chars[i] <= 0x7e

add_constraint arg_chars[36] == 0

set_memory 0xd0000000 argv[0]
set_memory 0xd0000010 argv[1]

add_to_stack 0xd0000000
add_to_stack 0xd0000010
add_to_stack &reg.esp
add_to_stack 2
add_to_stack 0x401f30

set_memory 0x413ad4 36 size=4 endness=Iend_LE

breakpoint (by_address 0x402f29)
exclude (by_address 0x402f3f)

run

