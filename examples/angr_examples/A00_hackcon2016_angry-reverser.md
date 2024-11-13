# ReverseMe example: HackCon 2016 - angry-reverser
## Context

Script author: Stanislas Lejay (github: [@P1kachu](https://github.com/P1kachu>))

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/hackcon2016_angry-reverser/yolomolo>)
and the script
[script](https://github.com/angr/angr-examples/tree/master/examples/hackcon2016_angry-reverser/solve.py>)

## Solution with dAngr:

```
load 'repo/examples/hackcon2016_angry-reverser/yolomolo'

add_symbol flag 20

set_blank_state addr=0x400646 add_options=[options.LAZY_SOLVES]

set_memory 0x606000 flag endness=BE

&reg.rdi = 0x606000

chops = chop_symbol &sym.flag 8
for c in chops :
    add_constraint c >= 0x30 && c <= 0x7f

breakpoint (by_address 0x405a6e)

avoids = [0x402c3c, 0x402eaf, 0x40311c, 0x40338b, 0x4035f8, 0x403868, 0x403ad5, 0x403d47, 0x403fb9, 0x404227, 0x404496, 0x40470a, 0x404978, 0x404bec, 0x404e59, 0x4050c7,0x405338, 0x4055a9, 0x4057f4, 0x405a2b]
for avoid in avoids:
    exclude (by_address avoid)


run

to_bytes (evaluate &sym.flag)

```
