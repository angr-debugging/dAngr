# Whitehat CTF 2015 - Crypto 400
   Script author: Yan Shoshitaishvili (github: @Zardus)
   Script runtime: 30 seconds
   Concepts presented: statically linked binary (manually hooking with function summaries), commandline argument, partial solutions

We solved this crackme with angr's help. The resulting script will help you
understand how angr can be used for crackme *assistance*, not a full-out solve.
Since angr cannot solve the actual crypto part of the challenge, we use it just
to reduce the keyspace, and brute-force the rest.

You can find this script [here](https://github.com/angr/angr-examples/tree/master/examples/whitehat_crypto400/solve.py)
and the binary [here](https://github.com/angr/angr-examples/tree/master/examples/whitehat_crypto400/whitehat_crypto400).

## Solution with dAngr:

setup of addresses used in program
addresses assume base address of
```    

load 'whitehat_crypto400' 

```
this is a statically-linked binary, and it's easer for angr if we use Python summaries for the libc functions

```
hook_function "glibc.__libc_start_main" 0x4018B0
hook_function "libc.memcpy" 0x422690
hook_function "libc.puts" 0x408F10
```
This is some anti-debugging initialization. It doesn't do much against angr, but wastes time
```
hook_function "stubs.ReturnUnconstrained" 0x401438
```
From playing with the binary, we can easily see that it requires strings of
length 8, so we'll hook the strlen calls and make sure we pass an 8-byte
string
```
def hook_length():
    &reg.rax = 8

hook_region hook_length 0x40168e 5
hook_region hook_length 0x4016BE 5
```
Here, we create the initial state to start execution. argv[1] is our 8-byte
string, and we add an angr option to gracefully handle unsupported syscalls
```
add_symbol 'arg1' 8
set_entry_state args=["crypto400", &sym.arg1] add_options=[options.BYPASS_UNSUPPORTED_SYSCALL]
```
and let's add a constraint that none of the string's bytes can be null
```

for b in (chop_symbol arg1 8):
    add_constraint b != 0
```
Now, we start the symbolic execution engine. We start at the beginning of the
program, and we want to reach the first stage of the crackme, which is at
0x4016A3. We also want to avoid some other addresses that are not interesting
to us.
```
add_breakpoint 0x4016A3
run

clear_breakpoints
add_breakpoint 0x4016B7
add_exclusion 0x4017D6
add_exclusion 0x401699
add_exclusion 0x40167D
run

clear_breakpoints
add_breakpoint 0x4017CF
run

clear_filters
add_breakpoint 0x401825
add_exclusion 0x401811

for i in range(8):
    m = &mem[0x6C4B20 + i->1]
    add_constraint m >= 0x21 && m <= 0x7e

```

Now get the possible values, for instance, as follows:
    
    possible_solutions = evaluate_n arg1 6500
    print possible_solutions

One caveat is that getting all possible values for all 8 bytes pushes a lot of complexity to the SAT solver, and it chokes.
To avoid this, we're going to get the solutions to 2 bytes at a time, and brute force the combinations.

```

possible_values = []
for i in range(0, 8, 2):
    append possible_values (evaluate_n &mem[0x6C4B20 + i->2] n=65536 dtype=bytes)

!(import itertools)
solutions_0 = !(tuple(itertools.product(*&vars.possible_values)))
solutions = !([b"".join(a) for a in &vars.solutions_0])

```
Test the solutions:
    
```
result = ""
for s in solutions:
    s = to_str s
    v = $(./repo/angr_examples/examples/whitehat_crypto400/whitehat_crypto400 &vars.s)
    if "FLAG IS:" in v:
        result = "input: " + s + " -> FLAG: " + v[18:]
        break
println result
```
# (END)

