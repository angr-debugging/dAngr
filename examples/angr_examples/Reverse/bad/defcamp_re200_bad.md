# defcamp re_200

println "This example is broken. The password is rotors"

load 'repo/angr_examples/examples/defcamp_r200/r200'

add_symbol password 6

set_entry_state 0x400886

exclude (by_stream "Incorrect password!")

breakpoint (by_stream nice)

run