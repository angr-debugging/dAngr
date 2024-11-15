# Beginner reversing example: little_engine

   Script author: Michael Reeves (github: @mastermjr)
   Script runtime: 3 min 26 seconds (206 seconds)
   Concepts presented:
   stdin constraining, concrete optimization with Unicorn

This challenge is similar to the csaw challenge below, however the reversing is
much more simple. The original code, solution, and writeup for the challenge can
be found at the b01lers github [here](https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine).

The angr solution script is [here](https://github.com/angr/angr-examples/tree/master/examples/b01lersctf2020_little_engine/solve.py)
and the binary is [here](https://github.com/angr/angr-examples/tree/master/examples/b01lersctf2020_little_engine/engine)


## Solution with dAngr:

setup of addresses used in program
addresses assume base address of
```    
base_addr = 0x100000
load 'repo/examples/b01lersctf2020_little_engine/engine' base_addr=base_addr auto_load_libs=True

```

length of desired input is 75 as found from reversing the binary in ghidra
need to add 4 times this size, since the actual array is 4 times the size
1 extra byte for first input

```

input_len = 75*4

flag_chars = []
for i in range(input_len):
    s = add_symbol ('flag_' + (to_str i)) 8
    append flag_chars s

to_symbol flag (flag_chars + ['\n'])

set_full_state args=["./engine"] add_options=options.unicorn stdin=&sym.flag

for c in flag_chars:
    add_constraint c < 0x7f && c > 0x20

```
Step until there is nothing left to be stepped.

```
run
```
Grab all finished states, that have the win function output in stdout
```
valid = -1
i=0
for x in (list_states deadended):
    select_state i 'deadended'
    out = dump_stdstream stdout
    i = i+1
    print out
    if b'Chugga' in out:
        valid = i
        break

print valid
select_state valid[0] 'deadended'
println (dump_stdstream stdin)


```
