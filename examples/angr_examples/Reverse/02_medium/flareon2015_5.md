# FlareOn 2015 - Challenge 5

   Script author: Adrian Tang (github: @tangabc)
   Script runtime: 2 mins 10 secs
   Concepts presented: Windows support

This is another [reversing challenge](https://github.com/angr/angr-examples/tree/master/examples/flareon2015_5/sender) from the FlareOn challenges.

"The challenge is designed to teach you about PCAP file parsing and traffic
decryption by reverse engineering an executable used to generate it. This is a
typical scenario in our malware analysis practice where we need to figure out
precisely what the malware was doing on the network"

For this challenge, the author used angr to represent the desired encoded output
as a series of constraints for the SAT solver to solve for the input.

For a detailed write-up please visit the author's post [here](http://0x0atang.github.io/reversing/2015/09/18/flareon5-concolic.html) and
you can also find the solution from the FireEye [here]((https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution5.pdf).


## Solution with dAngr:
Full writeup of the walkthrough:
http://0x0atang.github.io/reversing/2015/09/18/flareon5-concolic.html

Globals
```
LEN_PW = 0x22
ADDR_PW_ORI = 0
ADDR_PW_ENC = 0
ADDR_HASH = 0

GOAL_HASH = 'UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW=='
```

Define Hooks:
``` 
def hook_pw_buf():
    for i in range(LEN_PW):
        char_ori = &mem[(ADDR_PW_ORI + i)->1]
        &mem[ADDR_PW_ENC + i->1] = char_ori
    &reg.ebx = ADDR_PW_ENC

def hook_use_pw_buf():
    &reg.ecx = ADDR_PW_ENC

def hook_heap_alloc():
    &reg.eax = ADDR_HASH

```
Load and setup the binary
```
load 'flareon2015_5' auto_load_libs=False
```
Start with a blank state at the EIP after "key.txt" is read
```
set_blank_state addr=0x401198

```
Initialize global variables
```

ADDR_PW_ORI = &reg.ebp - 0x80004
ADDR_PW_ENC = ADDR_PW_ORI + 0x10000
ADDR_HASH = &reg.ebp - 0x40000

```
Setup stack to simulate the state after which the "key.txt" is read
```
&reg.esi = LEN_PW
for i in range(LEN_PW):
    sim = add_symbol 'pw' 1
    &mem[ADDR_PW_ORI+i->1] = sim
```
Hook instructions to use a separate buffer for the XOR-ing function
```
hook_region hook_pw_buf 0x401259 0 replace=False
hook_region hook_use_pw_buf 0x4011E7 0 replace=False
```
To avoid calling imports (HeapAlloc), retrofit part of the stack as temporary buffer to hold symbolic copy of the password
```
hook_region hook_heap_alloc 0x4011D6 5 replace=False
```
Explore the states until after the hash is computed
```
add_breakpoint 0x4011EC
run
```
Add constraints to make final hash equal to the one we want
Also restrict the hash to only printable bytes
```
len_hash = len GOAL_HASH
for i in range(len_hash):
    char = &mem[ADDR_HASH + i->1]
    oo = GOAL_HASH[i]
    o = !(ord(&vars.oo))
    add_constraint char >= 0x21 && char <= 0x7e && char == o
```
Solve for password that will result in the required hash
```

solution = evaluate &mem[ADDR_PW_ORI->LEN_PW] dtype=bytes
println solution
```

Flag: Sp1cy_7_layer_OSI_dip@flare-on.com