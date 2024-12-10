load 'repo/angr_examples/examples/0ctf_momo_3/momo'

ins_char = 0x81fe6e0
flag_char = 0x81fe6e4

after_fgets = 0x08049653
mov_congrats = 0x0805356e


size = mov_congrats - after_fgets




buff_name = ""
for var in get_stdin_variables:
    for n in &vars.var[0].variables:
        buffer_name = n

