# Fauxware

This is a basic script that explains how to use angr to symbolically execute a
program and produce concrete input satisfying certain conditions.

Binary, source, and script are found [here](https://github.com/angr/angr-examples/tree/master/examples/fauxware)

## Solution with dAngr:

```
load '00_fauxware'

add_symbol argv1 0xE

set_entry_state

def check_states():
    l = len &(list_states)
    l > 1

breakpoint (make_filter check_states)

run

inp0 = dump_stdstream stdin
select_state 1
inp1 = dump_stdstream stdin

result = ""
if b'SOSNEAKY' in inp0:
    result = inp0
else:
    result = inp1
println (strip result b'\x00')
```
