import argparse
from dAngr.cli.server import Server


def run():
    parser = argparse.ArgumentParser(description="dAngr Symbolic debugger.")
    parser.add_argument("-f", type=str, help="File to debug.", required=False)
    parser.add_argument("-s", type=str, help="Script to execute.",required=False)
    args = parser.parse_args()
    Server(args.f, args.s).start_server()


