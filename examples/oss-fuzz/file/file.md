# demo with real binary

## fuzz repository: https://github.com/file/file.git
## Issue: https://github.com/file/file/commit/473e039b48fd72660dd00f4b52a2880cc0dd5632
## https://issues.oss-fuzz.com/issues/42541665
## Vulnerability: Heap-Buffer-Overflow
## YAML: https://github.com/google/oss-fuzz-vulns/blob/main/vulns/file/OSV-2018-15.yaml


er zit een fout in de json parser
volgende code zou de fout kunnen triggeren met data de content van test_case

file_fuzz testcase: 
    loads magic.mgc in the back
    and then passes data in a file named testcase to magic_buffer
    contents of testcase should go to that buggy place (see Issue above)

Crash Type: Heap-buffer-overflow READ 1
Crash Address: 0x60a0000003b1 -> may be invalid
Crash State:
  json_parse_string
  json_parse
  json_parse_array

'''
load file

#ensure magic.mgc is found

#set args to test and provide as symbolic file



'''