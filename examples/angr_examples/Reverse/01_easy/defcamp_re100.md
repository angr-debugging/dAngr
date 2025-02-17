# defcamp re_100

This program takes an input using fgets from stdin. It then checks if the input is the correct password.
Lets set dAngr to start in the main function.

```
load 'defcamp_re100'
main_func = get_function_info main
set_blank_state addr=&vars.main_func.addr
```


The correct password should print a "Nice!", so lets put a breakpoint on that stream.
```
breakpoint (by_stream "Nice!")
run
```

Once the breakpoint hits we can get the password by dumping the stdin stream.

```
input = strip (dump_stdstream stdin) b'\x00'
println input
```