# 07_strcpy_test

This program lets us print a message when we give the correct password. The function that prints the message has a strcpy withouth boundschecks. And is vulnerable to a buffer overflow.

`./strcpy_test <password> <message>`

To do the buffer overflow we will need the correct password. 

The message and password are passed trough args, we set the password to a symbolic variable and we set the message to "Hacked!".
Then we put a breakpoint when our message is printed.  


```
load 'repo/angr_examples/examples/strcpy_find/strcpy_test'
add_symbol flag 30

set_entry_state args=["strcpy_test", &sym.flag, "Hacked!"]

get_function_info func

breakpoint (by_stream "Hacked!")
exclude (by_address 0x40061d)

run
evaluate &sym.flag
```