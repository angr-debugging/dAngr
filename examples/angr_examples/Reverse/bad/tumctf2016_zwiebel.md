# TUMCTF 2016 - zwiebel
   Script author: Fish
   Script runtime: 2 hours 31 minutes with pypy and Unicorn - expect much longer with CPython only
   Concepts presented: self-modifying code support, concrete optimization with Unicorn

This example is of a self-unpacking reversing challenge. This example shows how
to enable Unicorn support and self-modification support in angr. Unicorn support
is essential to solve this challenge within a reasonable amount of time -
simulating the unpacking code symbolically is *very* slow. Thus, we execute it
concretely in unicorn/qemu and only switch into symbolic execution when needed.

You may refer to other writeup about the internals of this binary. I didn't
reverse too much since I was pretty confident that angr is able to solve it :-)

The long-term goal of optimizing angr is to execute this script within 10
minutes. Pretty ambitious :P

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/tumctf2016_zwiebel/zwiebel) and the [script](https://github.com/angr/angr-examples/tree/master/examples/tumctf2016_zwiebel/solve.py).

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
    s = add_symbol ('flag_' + (to_str i)) 
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
