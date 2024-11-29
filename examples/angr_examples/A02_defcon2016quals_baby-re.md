# ReverseMe example: DEFCON Quals 2016 - baby-re

Authors David Manouchehri (github: [@Manouchehri](https://github.com/Manouchehri), Stanislas Lejay (github: [@P1kachu](https://github.com/P1kachu)) and Audrey Dutcher (github: @rhelmot).

Script runtime: 10 sec

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/baby-re)
and the [script](https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/solve.py)

## Solution with dAngr:

```

load 'A02_defcon2016quals_baby-re'

flag_chars = []
for i in range(13):
    symbol = add_symbol ('flag_' + (to_str i)) 4
    append flag_chars symbol

def scanf(fmt, ptr):
    count = get_from_state scanf_count
    sn = !('flag_%d' % &vars.count)
    s = get_symbol sn
    set_memory ptr s 4
    count = count + 1
    add_to_state scanf_count count

hook_function scanf '__isoc99_scanf'

set_blank_state add_options=[options.LAZY_SOLVES]

add_to_state scanf_count 0

breakpoint (by_address 0x4028E9)
exclude (by_address 0x402941)

run
print "Flag: "
for i in range(13):
    s_i = evaluate (get_symbol ('flag_%d' % i))
    print (to_str (rstrip s_i b'\x00'))
println

```
