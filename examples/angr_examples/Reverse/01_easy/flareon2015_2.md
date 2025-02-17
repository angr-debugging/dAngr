# Flareon 2015  challenge 2

In this challenge the binary takes input from the std_input_handle file. This time we set the stdin stream to a symbolic value.
We then set a breakpoint when the output "success" is printed.

```
load 'flareon2015_2'

add_symbol 'password' 0x32
set_entry_state stdin=&sym.password

breakpoint (by_stream "success")
run

password = strip (evaluate &sym.password) b'\x00'
println password
```