import argparse
from dAngr.cli.server import Server

def run(debug_file_path=None, script_path=None):
    Server(debug_file_path, script_path).start_server()


