# Fauxware

This is a basic script that explains how to use angr to symbolically execute a
program and produce concrete input satisfying certain conditions.

Binary, source, and script are found [here](https://github.com/angr/angr-examples/tree/master/examples/fauxware)

## Solution with dAngr:


An other way to check if dAngr has found the password is to check where we get multiple branches. 
We do that by adding a breakpoint with a filter check_states.

```
load 'fauxware'

def check_states():
    state_len = len &(list_states)
    state_len > 1

breakpoint (make_filter check_states)

run

println (strip (dump_stdstream stdin) b'\x00')
```
