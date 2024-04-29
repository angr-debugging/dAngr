
# dAngr Example: basic_example

The example source code ofthe binary is available in example.c. Build the example and run the following commands in the debubber.

This example demonstrates how to use the debugger to set function prototypes, function calls, and retrieve return values during symbolic execution.

## Commands
1. Start dAngr and load the binary:

```bash
(dAngr)> load example
```

2. Optionally Load SimProcedure hooks from a file (e.g.,`example_hooks.py`):

```bash
(dAngr)> load_hooks example_hooks.py
```

3. Set the function prototype for `processMessage`:

```bash
(dAngr)> set_function_prototype int processMessage(char*, int, char*)
```

4. Set the function call for `processMessage` with parameters `abc`, 2, and a buffer filled with 0s :

```bash
(dAngr)> set_function_call processMessage('abc',2,b'000000000')
```

5. Run the binary:

```bash
(dAngr)> start
```

6. Get the return value of the `processMessage` function:

```bash
(dAngr)> get_return_value
```

