# dAngr Example: AES_example
in aes_example.c is the source code of the binary aes_example. This files creates an AES key and encrypt a message.

## Commands
1. Start dAngr and load the binary:
```bash
(dAngr)> load aes_example
```

2. Set the function prototype for `obfuscate`:

```bash
(dAngr)> set_function_prototype char* obfuscate(char*, char*)
```

3. Set the function call for `obfuscate` with parameters `VerifySafeSecret` and `12345678910`:
```bash
(dAngr)> set_function_call obfuscate("VerifySafeSecret","12345678910")

```

4. Continue the binary:
```bash
(dAngr)> continue
```
4. Get the return value of the `obfuscate` function:

```bash
(dAngr)> get_return_value
```

```bash
(dAngr)> get_string_memory 0xc0000000 
```