import os, pytest

from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection

from unittest.mock import Mock


class TestSearchTechniques:
    old_dir = os.getcwd()

    def setup_method(self):
        os.chdir(os.path.dirname(__file__))

    def teardown_method(self):
        os.chdir(self.old_dir)


    @pytest.fixture
    def conn(self):
        c = CliConnection()
        c.send_result = Mock()
        c.send_info = Mock()
        c.send_error = Mock()
        return c

    @pytest.fixture
    def dbg(self,conn):
        dbg = CommandLineDebugger(conn)
        assert dbg.handle("load dfs_bfs_demo")
        return dbg


    # - DFS

    def test_dfs(self, dbg, conn: CliConnection):
        assert dbg.handle("add_breakpoint 0x4012a6")
        assert dbg.handle("add_breakpoint 0x4012b7")
        assert dbg.handle("add_breakpoint 0x4012d4")
        assert dbg.handle("add_breakpoint 0x4012e5")
        assert dbg.handle("add_breakpoint 0x401302")
        assert dbg.handle("add_breakpoint 0x401313")
        assert dbg.handle("sst DFS")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012a6.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012d4.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x401302.")
        assert dbg.handle("run")


    # - BFS

    def test_bfs(self, dbg, conn: CliConnection):
        assert dbg.handle("add_breakpoint 0x4012a6")
        assert dbg.handle("add_breakpoint 0x4012b7")
        assert dbg.handle("add_breakpoint 0x4012d4")
        assert dbg.handle("add_breakpoint 0x4012e5")
        assert dbg.handle("add_breakpoint 0x401302")
        assert dbg.handle("add_breakpoint 0x401313")
        assert dbg.handle("sst BFS")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012b7.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012a6.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012e5.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012d4.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012e5.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x4012d4.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x401313.")
        assert dbg.handle("run")
        conn.send_info.assert_called_with("Break: Address Filter: 0x401302.")


    # - TS

    def test_ts(self, dbg, conn: CliConnection):
        assert dbg.handle("add_breakpoint 0x4012a6")
        assert dbg.handle("add_breakpoint 0x4012b7")

        assert dbg.handle("sst TS target_address=0x4012b7")
        assert dbg.handle("run")

        conn.send_info.assert_called_with("Break: Address Filter: 0x4012b7.")

        assert dbg.handle("load dfs_bfs_demo")
        assert dbg.handle("bc")
        assert dbg.handle("add_breakpoint 0x4012d4")
        assert dbg.handle("add_breakpoint 0x4012e5")

        assert dbg.handle("sst TS target_address=0x4012d4")
        assert dbg.handle("run")

        conn.send_info.assert_called_with("Break: Address Filter: 0x4012d4.")

        assert dbg.handle("load dfs_bfs_demo")
        assert dbg.handle("bc")
        assert dbg.handle("add_breakpoint 0x401302")
        assert dbg.handle("add_breakpoint 0x401313")

        assert dbg.handle("sst TS target_address=0x401313")
        assert dbg.handle("run")

        conn.send_info.assert_called_with("Break: Address Filter: 0x401313.")