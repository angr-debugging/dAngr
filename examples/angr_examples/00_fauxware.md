# Fauxware

This is a basic script that explains how to use angr to symbolically execute a
program and produce concrete input satisfying certain conditions.

Binary, source, and script are found [here](https://github.com/angr/angr-examples/tree/master/examples/fauxware)

## Solution with dAngr:

```
load '00_fauxware'

add_symbol argv1 14

def check_states():
    l = len &(list_states)
    l > 1

breakpoint (make_filter check_states)

run

println (strip (dump_stdstream stdin) b'\x00')
```
