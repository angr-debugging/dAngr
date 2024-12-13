# Crackme

This is an easy example from ais3 where we get the binary 'crackme'. 
The binary prompts for a secret key, it checks if the key is valid. A valid key results into a string that prints "Correct! that is the secret key!"


Lets start by loading in the binary and inspecting the main function.

```
load 'crackme'
decompiled_function main
```

The main function has to parameters, a0 and a1. This is probably argc and argv.
You could check what gets printed if 'a0 != 2'
`evaluate &mem[0x4006c8->0x26]`

So the binary takes our key using the arguments, we can use dAngr to assign a symbolic value to argv[1] and break when a state reaches the "Correct key" branch.
The first argument (argv[0]) is the filename of the executable, in this case it doesn't really mather so we can just set if to 'file'.
```
add_symbol arg1 100

set_entry_state args=['file', &sym.arg1]
breakpoint (by_stream "Correct!")
run
```

Once a state reaches a branch that prints the desired output, we can evaluate what the value of arg1 is in that state. 

```
flag = strip (evaluate &sym.arg1) b'\x00'
println flag
```