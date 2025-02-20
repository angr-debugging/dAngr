
from unittest.mock import Mock, Mock
import pytest

from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
import subprocess



class TestExamples:


    @pytest.fixture
    def conn(self):
        c = CliConnection()
        c.send_result = Mock()
        c.send_info = Mock()
        c.send_error = Mock()
        return c


    # results = {
    #     '00_angr_find.md': b'YXIACZSW',
    #     '01_angr_avoid.md': b'JLVUSGJZ',
    #     '02_angr_find_condition.md': b'OHYJUMBE',
    #     '03_angr_symbolic_registers.md': 'e9b37483 7aab5fde 8f5b48ea',
    #     '04_angr_symbolic_stack.md':'2089710965 12847883',
    #     '05_angr_symbolic_memory.md': 'OJQVXIVX LLEAOODW UVCWUVVC AJXJMVKA',
    #     '06_angr_symbolic_dynamic_memory.md':'OFIJHOXV FBQISOZO',
    #     "07_angr_symbolic_file.md": 'OBAXRUZT',
    #     "08_angr_constraints.md": 'ZEVKWROAYILRPZYB',
    #     "09_angr_hooks.md": b'QREPXOHPJPOQKQLKNOBMULEMGMLNHNIH',
    #     "10_angr_simprocedures.md": b'MTMDRONBBNSAAMNS',
    #     "11_angr_sim_scanf.md": '1447907916 1146768724',
    #     "13_angr_static_binary.md": b'EADQYLAR',
    #     "14_angr_shared_library.md": 'TSDLQKWZ',
    #     "15_angr_arbitrary_read.md": '2358019 AAAAAAAAAAAAAAAAWISO'
    # }

    # 
    # def test_oregonctf_examples(self, conn):
    #     # for each .md file in the examples/malware.oregonctf.org directory run the script
    #     # and check the output

    #     for file in sorted(os.listdir("examples/malware.oregonctf.org")):
    #         if file.endswith(".md"):
    #             print(file)
    #             dbg = CommandLineDebugger(conn)
    #             dbg.handle("run_script 'examples/malware.oregonctf.org/" + file + "'")
    #             assert conn.send_result.call_args[0][0] == self.results[file], f"Failed on {file}"
    #             conn.send_result.reset_mock()
    #             conn.send_info.reset_mock()
    #             conn.send_error.reset_mock()
    
    
    def test_00_angr_find(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/00_angr_find.md'")
        assert conn.send_result.call_args[0][0] == b'YXIACZSW'
    
    
    def test_01_angr_avoid(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/01_angr_avoid.md'")
        assert conn.send_result.call_args[0][0] == b'JLVUSGJZ'

    
    def test_02_angr_find_condition(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/02_angr_find_condition.md'")
        assert conn.send_result.call_args[0][0] == b'OHYJUMBE'
    
    
    def test_03_angr_symbolic_registers(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/03_angr_symbolic_registers.md'")
        assert conn.send_result.call_args[0][0] == 'e9b37483 7aab5fde 8f5b48ea'

    
    def test_04_angr_symbolic_stack(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/04_angr_symbolic_stack.md'")
        assert conn.send_result.call_args[0][0] == '2089710965 12847883'
    
    
    def test_05_angr_symbolic_memory(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/05_angr_symbolic_memory.md'")
        assert conn.send_result.call_args[0][0] == 'OJQVXIVX LLEAOODW UVCWUVVC AJXJMVKA'

    
    def test_06_angr_symbolic_dynamic_memory(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/06_angr_symbolic_dynamic_memory.md'")
        assert conn.send_result.call_args[0][0] == 'OFIJHOXV FBQISOZO'

    
    def test_07_angr_symbolic_file(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/07_angr_symbolic_file.md'")
        assert conn.send_result.call_args[0][0] == 'OBAXRUZT'

    
    def test_08_angr_constraints(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/08_angr_constraints.md'")
        assert conn.send_result.call_args[0][0] == 'ZEVKWROAYILRPZYB'

    
    def test_09_angr_hooks(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/09_angr_hooks.md'")
        assert conn.send_result.call_args[0][0] == b'QREPXOHPJPOQKQLKNOBMULEMGMLNHNIH'

    
    def test_10_angr_simprocedures(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/10_angr_simprocedures.md'")
        assert conn.send_result.call_args[0][0] == b'MTMDRONBBNSAAMNS'

    
    def test_11_angr_sim_scanf(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/11_angr_sim_scanf.md'")
        assert conn.send_result.call_args[0][0] == '1447907916 1146768724'

    
    def test_13_angr_static_binary(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/13_angr_static_binary.md'")
        assert conn.send_result.call_args[0][0] == b'EADQYLAR'

    
    def test_14_angr_shared_library(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/14_angr_shared_library.md'")
        assert conn.send_result.call_args[0][0] == 'TSDLQKWZ'

    def test_15_angr_arbitrary_read(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/15_angr_arbitrary_read.md'")
        assert conn.send_result.call_args[0][0][:7] == '2358019'
        assert conn.send_result.call_args[0][0][-5:-1] == 'WISO'

    
    def test_16_angr_arbitrary_write(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/16_angr_arbitrary_write.md'")
        assert conn.send_result.call_args[0][0][:7] == '6712341'
        assert conn.send_result.call_args[0][0][8:16] == 'NEDVTNOP'
        assert conn.send_result.call_args[0][0][-4:] == '<RCM'

    
    def test_17_angr_arbitrary_jump(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/malware.oregonctf.org/17_angr_arbitrary_jump.md'")
        assert conn.send_result.call_args[0][0] == 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCPRCMCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    
    def test_crackme(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/01_easy/crackme.md'")
        assert conn.send_result.call_args[0][0] == "b'ais3{I_tak3_g00d_n0t3s}'"
    

    def test_defcamp_re100(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/01_easy/defcamp_re100.md'")
        assert conn.send_result.call_args[0][0] == "b'Code_Talkers'"
    
    def test_fauxware(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/01_easy/fauxware.md'")
        assert conn.send_result.call_args[0][0] == "b'SOSNEAKY'"

    def test_flareon2015_2(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/01_easy/flareon2015_2.md'")
        assert conn.send_result.call_args[0][0] == "b'a_Little_b1t_harder_plez@flare-on.com'"

    def test_mma_howtouse(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/01_easy/mma_howtouse.md'")
        assert conn.send_result.call_args[0][0] == "b'MMA{fc7d90ca001fc8712497d88d9ee7efa9e9b32ed8}'"
    
    def test_securityfest_fairlight(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/01_easy/securityfest_fairlight.md'")
        assert conn.send_result.call_args[0][0] == b'4ngrman4gem3nt'
    
    def test_asisctffinal2015_fake(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/02_medium/asisctffinals2015_fake.md'")
        assert conn.send_result.call_args[0][0] == "b'ASIS{f5f7af556bd6973bd6f2687280a243d9}'"
    
    def test_defcon2016quals_baby_re(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/02_medium/defcon2016quals_baby-re.md'")
        assert conn.send_result.call_args[0][0] == 'Math is hard!'

    def test_flareon2015_5(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/02_medium/flareon2015_5.md'")
        assert conn.send_result.call_args[0][0] == "b'Sp1cy_7_layer_OSI_dip@flare-on.com'"

    def test_google2016_unbreakable_1(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/02_medium/google2016_unbreakable.md'")
        assert conn.send_result.call_args[0][0] == 'CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}'

    def test_hackcon2016_angry_reverser(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/02_medium/hackcon2016_angry-reverser.md'")
        assert conn.send_result.call_args[0][0] == b'HACKCON{VVhYS04ngrY}'

    def test_0ctf_trace(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/03_hard/0cft_trace.md'")
        assert conn.send_result.call_args[0][0] == "0ctf{tr135m1k5l96551s9l5r}"
    
    def test_whitehat_crypto400(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/Reverse/03_hard/whitehat_crypto400.md'")
        assert conn.send_result.call_args[0][0] == b'WhiteHat{I_Love_Angr_And_Z3_Solver}'
    
    def test_cgc_identification(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/vuln_exploit/01_easy/cgc_identification.md'")
        exploit_str = eval(conn.send_result.call_args[0][0])
        assert len(exploit_str) >= 92
        assert chr(exploit_str[0]) == '^'
    
    def test_insomnihack_aeg(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/vuln_exploit/02_medium/insomnihack_aeg.md'")
        exploit_str = eval(conn.send_result.call_args[0][0])
        # (cat file; echo echo BUMU) | ./examples/angr_examples/repo/angr_examples/examples/insomnihack_aeg/demo_bi
        exploit_str = str(exploit_str).replace("'", '"')
        print_exploit_str = f"python -c 'import sys; sys.stdout.buffer.write({exploit_str})'"
        test = subprocess.check_output(f'({print_exploit_str}; echo echo pwned) | ./examples/angr_examples/vuln_exploit/02_medium/demo_bin', shell=True)
        assert test == b'pwned\n'
    
    def test_mbrainfuzz(self, conn):
        dbg = CommandLineDebugger(conn)
        dbg.handle("run_script 'examples/angr_examples/vuln_exploit/03_hard/mbrainfuzz.md'")
        

