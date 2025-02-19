# MMA howtouse

In this example we get a dll binary thas has the function 'fnhowtouse'. This function doesn't make any calls so exists in one basic block.
When we use a step in dAngr the state terminates. 


```
load 'mma_howtouse.dll' base_addr=0x10000000
set_entry_state 0x10001130
def test():
    set_register eax 0

hook_region test 0x100011bf

flag = b""
fn_howToUse = 0x10001130
for i in range(45):
    func_result = evaluate (get_callable_function fn_howToUse i)
    flag = flag + (strip (func_result) b'\x00')

println flag
```

  