import argparse
from dAngr.run import run

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="dAngr Symbolic debugger.")
    parser.add_argument("-f", type=str, help="File to debug.", required=False)
    parser.add_argument("-s", type=str, help="Script to execute.",required=False)
    args = parser.parse_args()
    run(debug_file_path=args.f, script_path=args.s)
