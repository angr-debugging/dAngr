
load 'repo/angr_examples/examples/CADET_00001/CADET_00001' auto_load_libs=False
keep_unconstrained

exclude (by_address 0x80482f1)
wz
def stop_condition():
    unc = len (list_states unconstrained)
    return unc == 0


while stop_condition:
    step


print "buffer overflow with input: "
println (dump_stdstream stdin)

breakpoint (by_stream "EASTER EGG!")
run

print "Input to get the easter egg"
println (dump_stdstream stdin)

    
    


