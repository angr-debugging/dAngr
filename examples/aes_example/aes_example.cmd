load aes_example
set_function_prototype char* obfuscate(char*, char*)
set_function_call obfuscate("VerifySafeSecret","12345678910")
continue
get_return_value
get_string_memory 0xc0000000