# MMA howtouse

In this example we get a dll binary thas has the function 'fnhowtouse'. This function doesn't make any calls so exists in one basic block.
When we use a step in dAngr the state terminates. 


```
load 'mma_howtouse.dll' base_addr=0x10000000
set_entry_state 0x10001130
def test():
    set_register eax 0

hook_region test 0x100011bf

str = ""
for i in range(45):
    str = str + (to_str (strip (evaluate (get_callable_function 0x10001130 i)) b'\x00'))

println str
```

  