# Crackme

This is an easy example from ais3 where we get the binary crackme. 
The binary prompts for a secret key, it checks if the key is valid. A valid key results into a string that prints: Correct! that is the secret key!


Lets start by loading in the binary and inspecting the main function.

```
load 'crackme'
decompiled_function main
```

The main function has to parameters, a0 and a1. This is probably argc and argv.
You could check the string that gets printed if 'a0 != 2'
`evaluate &mem[0x4006c8->0x26]`

It tells us that we have to enter the secret key, indicating that our assumption was indeed correct.
Lets see what the other two strings are,
```
evaluate &mem[0x4006f0->0x26]
evaluate &mem[0x400718->0x26]
```

The first one prints: b'Correct! that is the secret key!'
and the second one prints: b"I'm sorry, that's the wrong secret key"

Now we have a good understanding of the binary, it takes our key using the program arguments. Verifies it somehow and then checks if the result is true or false.

We can use dAngr to assign a symbolic value to argv[1], break when a state reaches the "Correct key" branch.
The first argument (argv[0]) is the filename of the executable, in this case it doesn't really mather so we can just set if to 'file', the second argument is our bit-vector.
We could set a breakpoint on the entire string, but a part of the string also works.
```
add_symbol arg1 100

set_entry_state args=['file', &sym.arg1]
breakpoint (by_stream "Correct!")
run
```

We now have a state in the desired branch, allowing us to print the flag by evaluating our symbolic variable.

```
flag = strip (evaluate &sym.arg1) b'\x00'
println flag
```

(Flag: ais3{I_tak3_g00d_n0t3s})