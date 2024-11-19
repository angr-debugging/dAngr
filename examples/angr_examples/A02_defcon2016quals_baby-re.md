# ReverseMe example: DEFCON Quals 2016 - baby-re

Authors David Manouchehri (github: [@Manouchehri](https://github.com/Manouchehri), Stanislas Lejay (github: [@P1kachu](https://github.com/P1kachu)) and Audrey Dutcher (github: @rhelmot).

Script runtime: 10 sec

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/baby-re)
and the [script](https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/solve.py)

## Solution with dAngr:

```

load 'A02_defcon2016quals_baby-re'


for i in range(13):
    sn = !('flag_%d' % &vars.i)
    add_symbol sn 4

def scanf(fmt,ptr):
    cnt = get_from_state scanf_cnt
    sn = !('flag_%d' % &vars.cnt)
    s = get_symbol sn
    set_memory ptr s 4
    cnt = cnt + 1
    add_to_state scanf_cnt cnt

hook_function scanf '__isoc99_scanf'

set_blank_state add_options=[options.LAZY_SOLVES]

add_to_state scanf_cnt 0

breakpoint (by_address 0x4028E9)
exclude (by_address 0x402941)

run

for i in range(13):
    cnt = get_from_state scanf_cnt
    sn = !('flag_%d' % &vars.i)
    s = get_symbol sn
    m = &(evaluate s)
    c = !(chr(&vars.m[0]))
    print c
    if i==12:
        println

```
