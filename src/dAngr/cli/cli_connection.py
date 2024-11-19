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

    def _indent(self, data):
         return " "*self.indent + str(data).replace("\n", "\n" + " "*self.indent).replace("\t", " "*self.indent)

    def _escape(self, data, esscape_html=True):
        # indent data
        # replace non-printable characters with their hex representation
        data = "".join([c if c.isprintable() or c in ['\r','\n', '\t'] else f"\\x{ord(c):02x}" for c in str(data)])
        return html.escape(data ) if esscape_html else data
    
    def send_result(self, data, newline:bool=True, style=None):
        if data is None:
            return
        if newline:
            conc = "\n"
        else: conc = ""
        # if data is a list, print each element per line
        data = conc.join([str(x) for x in data]) if isinstance(data, list) else data
        #if data is a dictionary, print each key value pair per line
        data = conc.join([f"{k}: {v}" for k,v in data.items()]) if isinstance(data, dict) else data
        #if data is not a str  by now, convert it to a string
        data = str(data) if not isinstance(data, str) else data

        _data = data
        if newline:
            data = self._indent(data)
        #replace newlines with newlines and 4 spaces
        data = self._escape(data, style is None)
        #get total length of entries in self._output
        l = sum([len(x) for x in self.output]+[len(data)])

        if not style and l > 1000:
            if self._first:
                self._first = False
                print_formatted_text(HTML(self._escape(_data[:1000])),style=style, end = conc)
                print_formatted_text(HTML("<gray>Output too long, type 'less' to view</gray>"),style=style)
        else:
            print_formatted_text(HTML(data),style=style, end=conc)
        self.output.append((data.lstrip(),style))

    def send_output(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<skyblue>    > {data}</skyblue>"),style=style)

    def send_info(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<green>    Info: {data}</green>"),style=style)

    def send_warning(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<yellow>    Warning: {data}</yellow>"),style=style)

    def send_error(self, data, style=None):
        #replace newlines with newlines and 4 spaces
        data = self._escape(data)
        print_formatted_text(HTML(f"<red>    {data}</red>"),style=style)
