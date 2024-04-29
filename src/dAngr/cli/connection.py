from prompt_toolkit import HTML, print_formatted_text
import html
import re

class CliConnection:

    def __init__(self):
        self.indent = 4
    # async def send(self, data):
    #     if isinstance(data, Exception):
    #         print(data, file=sys.stderr)
    #     else:
    #         print(data)
        # try:
        #     print(f"    \033[94m{cmd.executeCmd(args)}\033[0m")
        # except CommandError as e:
        #     print(f"    \033[91m{e}\033[0m")
    def _escape(self, data):
        return html.escape(data )
        # return data.replace("&", "&amp").replace("<", "&lt").replace(">", "&gt").replace("\"", "&quot").replace("'", "&apos")
    
    
    async def send_event(self, data):
        #replace newlines with newlines and 4 spaces
        data = self._escape(str(data).replace("\n", "\n" + " "*self.indent))
        print_formatted_text(HTML(f"{data}"))

    async def send_output(self, data):
        #replace newlines with newlines and 4 spaces
        data = self._escape(str(data).replace("\n", "\n" + " "*self.indent))
        print_formatted_text(HTML(f"<skyblue>    > {data}</skyblue>"))

    async def send_error(self, data):
        #replace newlines with newlines and 4 spaces
        data = self._escape(str(data).replace("\n", "\n" + " "*self.indent))
        print_formatted_text(HTML(f"<red>    {data}</red>"))
