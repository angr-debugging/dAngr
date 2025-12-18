import argparse
from dAngr.cli.server import Server
from dAngr.MCP.server import dAngrMCP
import threading

def run():
    parser = argparse.ArgumentParser(description="dAngr Symbolic debugger.")
    parser.add_argument("-f", type=str, help="File to debug.", required=False)
    parser.add_argument("-s", type=str, help="Script to execute.",required=False)
    args = parser.parse_args()
    cli_server = Server(args.f, args.s)
    mcp = dAngrMCP(cli_server.dbg)
    threading.Thread(target=mcp.run, daemon=True).start()
    cli_server.start_server()


