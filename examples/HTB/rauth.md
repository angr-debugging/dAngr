````
load '../HTB/rauth' auto_load_libs=True

input_len = 32

flag_chars = []
for i in range(input_len):
    s = add_symbol ('flag_' + (to_str i)) 1
    append flag_chars s

to_symbol flag (append flag_chars '\n')



set_entry_state 0x406460 args=["./rauth"] stdin=&sym.flag base_addr=0

for c in flag_chars:
    if c != '\n':
        add_constraint c < 0x7f && c > 0x20
 
def rust_print():
    pntr = (to_int (evaluate (get_memory &reg.rdi 4 endness=LE)))
    println "The argument points to: "
    println (to_hex pntr)
 
    pntr2 = (to_int (evaluate (get_memory pntr 4 endness=LE)))
    println "And that points to: "
    println pntr2
    text = to_str (evaluate (get_memory pntr2 100))
    for char in text:
        if char == '\n':
            break
        print char
    println ""

hook_function rust_print 0x408530

exclude (by_address 0x4069c6)
exclude (by_address 0x406a9e)
exclude (by_address 0x40632e)
exclude (by_address 0x40630f)
exclude (by_address 0x406326)


breakpoint (by_address 0x406846)
run
```