# MMA howtouse

load 'repo/angr_examples/examples/mma_howtouse/howtouse.dll' base_addr=0x10000000

str = ""
for i in range(45):
    str = str + (to_str (strip (evaluate (get_callable_function 0x10001130 i)) b'\x00'))

println str