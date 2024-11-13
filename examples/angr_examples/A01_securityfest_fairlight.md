# ReverseMe example: SecurityFest 2016 - fairlight

Script author: chuckleberryfinn (github: [@chuckleberryfinn](https://github.com/chuckleberryfinn))

Script runtime: ~20 seconds

A simple reverse me that takes a key as a command line argument and checks it against 14 checks. Possible to solve the challenge using angr without reversing any of the checks.

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/securityfest_fairlight/fairlight)
and the [script](https://github.com/angr/angr-examples/tree/master/examples/securityfest_fairlight/solve.py)

## Solution with dAngr:

```
load 'repo/examples/securityfest_fairlight/fairlight'

add_symbol argv1 0xE

set_entry_state args=["./fairlight", &sym.argv1]


breakpoint (by_address 0x4018f7)
exclude (by_address 0x4018f9)

run

to_bytes (evaluate &sym.argv1)

```
