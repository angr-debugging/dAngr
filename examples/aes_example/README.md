# dAngr Example: AES_example
An AES encrypted message is created. The AES key is ininitialized using an obfuscated key.\nThis obfuscated key is created based on a secret and randomVal\n

The goal of reverse engineering would be to find the obfuscated key used to genenerate an AES Key\n\n
Manually reversing the obfuscate function, could take a lot of time in the case of a more complex obfuscation algorithm\n
This is where dAngr comes in, instead of spending time on reversing the obfuscation algorithm to recreate the obfuscated key,\nwe can simply step though this code using dAngr and get the obfuscated key\n
dAngr provides a gdb like interface, and also works on non-native binaries.\n


(In a more realistic scenario, the random value and secret would not be discoverable in the same file in cleartext ;)
## Commands
1. Start dAngr and load the binary:
```bash
load "aes_example"
unconstrained_fill
```

2. Set the function prototype for *obfuscate*:

```bash
set_function_prototype "char* obfuscate( char* , char* )"
```

3. Set the function call for *obfuscate* with parameters *VerifySafeSecret* and *12345678910*:
```bash
set_function_call "obfuscate('VerifySafeSecret','12345678910')"

```

4. Continue the binary:
```bash
run
```
4. Get the return value of the *obfuscate* function:

```bash
to_str (get_return_value)
```
