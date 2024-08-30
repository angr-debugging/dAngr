from typing import List, Tuple
from prompt_toolkit import HTML, print_formatted_text
import html

from dAngr.angr_ext.connection import Connection
from prompt_toolkit.styles import Style

class CliConnection(Connection):

    def __init__(self):
        super().__init__()
        self.indent = 4
        self._history:List[List[Tuple[str,Style|None]]] = [[]]
        # self._output:List[Tuple[str,Style|None]] = []
        self._first = True

    @property
    def output(self)->List[Tuple[str,Style|None]]:
        return self._history[-1]
    
    @output.setter
    def output(self, value:List[Tuple[str,Style|None]]):
        self._history[-1] = value
    
    @property
    def history(self)->List[List[Tuple[str,Style|None]]]:
        return self._history
    
    def clear_history(self):
        self._history = [[]]
        self._first = True

    def clear_output(self):
        if len(self._history[-1])!=0:
            self._history.append([])
        self._first = True
        
    # async def send(self, data):
    #     if isinstance(data, Exception):
    #         print(data, file=sys.stderr)
    #     else:
    #         print(data)
        # try:
        #     print(f"    \033[94m{cmd.executeCmd(args)}\033[0m")
        # except CommandError as e:
        #     print(f"    \033[91m{e}\033[0m")
    def _escape(self, data, esscape_html=True):
        # indent data
        data = " "*self.indent + str(data).replace("\n", "\n" + " "*self.indent).replace("\t", " "*self.indent)
        return html.escape(data ) if esscape_html else data
        # return data.replace("&", "&amp").replace("<", "&lt").replace(">", "&gt").replace("\"", "&quot").replace("'", "&apos")
    
    
    async def send_result(self, data, style=None):
        if not data:
            return
        _data = data
        #replace newlines with newlines and 4 spaces
        data = self._escape(data, style is None)
        #get total length of entries in self._output
        l = sum([len(x) for x in self.output]+[len(data)])

        if not style and l > 1000:
            if self._first:
                self._first = False
                print_formatted_text(HTML(self._escape(_data[:1000])),style=style)
                print_formatted_text(HTML("<gray>Output too long, use 'less' to view</gray>"),style=style)
        else:
            print_formatted_text(HTML(data),style=style)
        self.output.append((data.lstrip(),style))

    async def send_output(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<skyblue>    > {data}</skyblue>"),style=style)

    async def send_info(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<green>    Info: {data}</green>"),style=style)

    async def send_warning(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<yellow>    Warning: {data}</yellow>"),style=style)

    async def send_error(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<red>    {data}</red>"),style=style)
