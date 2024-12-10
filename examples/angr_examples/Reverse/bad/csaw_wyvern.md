# CSAW CTF 2015 Quals - Reversing 500, "wyvern"
   Script author: Audrey Dutcher (github: @rhelmot)
   Script runtime: 15 mins
   Concepts presented: stdin constraining, concrete optimization with Unicorn

angr can outright solve this challenge with very little assistance from the
user. The script to do so is [here](https://github.com/angr/angr-examples/tree/master/examples/csaw_wyvern/solve.py)
and the binary is [here](https://github.com/angr/angr-examples/tree/master/examples/csaw_wyvern/wyvern).

## Solution with dAngr:
Load the binary. This is a 64-bit C++ binary, pretty heavily obfuscated.
Its correct emulation by angr depends heavily on the libraries it is loaded with,
so if this script fails, try copying to this dir the .so files from our binaries repo: https://github.com/angr/binaries/tree/master/tests/x86_64

```    
load 'repo/examples/csaw_wyvern/wyvern

```
It's reasonably easy to tell from looking at the program in IDA that the key will be 29 bytes long, and the last byte is a newline. Let's construct a value of several symbols that we can add constraints on once we have a state.
```
flag_chars = []
for i in range(28):
    s = add_symbol ('flag_' + (to_str i)) 1
    append flag_chars s

to_symbol flag (append flag_chars '\n')

```
This block constructs the initial program state for analysis. Because we're going to have to step deep into the C++ standard libraries for this to work, we need to run everyone's initializers. The full_init_state will do that. In order to do this peformantly, we will use the unicorn engine!
```

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
valid = []
i=0
for x in (list_states deadended):
    select_state i 'deadended'
    out = dump_stdstream stdout
    i = i+1
    print out
    if b'Chugga' in out:
        append valid x
        break

select_state valid[0]
println (dump_stdstream stdin)


```
