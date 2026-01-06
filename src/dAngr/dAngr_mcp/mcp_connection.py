from dAngr.angr_ext.connection import Connection
from dAngr.cli.cli_connection import CliConnection


class McpConnection(Connection):

    def __init__(self, cli_connection:CliConnection|None=None):
        self.cli = cli_connection
        self.info = []
        self.output = []
        super().__init__()
    
    def send_result(self, data, newline:bool=True, style=None):
        if self.cli:
            self.cli.send_result(data, newline, style)

    def send_output(self, data, style=None):
        if self.cli:
            self.cli.send_output(data, style)
        self.output.append(data)

    def send_info(self, data, style=None):
        if self.cli:
            self.cli.send_info(data, style)
        self.info.append(data)
        
    
    def send_warning(self, data, style=None):
        if self.cli:
            self.cli.send_warning(data, style)

    def send_error(self, data, style=None):
        if self.cli:
            self.cli.send_error(data, style)

    def clear_output(self):
        if self.cli:
            self.cli.clear_output()
    