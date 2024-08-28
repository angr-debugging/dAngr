
import claripy
from dAngr.exceptions import DebuggerCommandError
from dAngr.utils.utils import StreamType, convert_argument
from .base import BaseCommand

class MemoryCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    async def dump_stdstream(self, stream_type: StreamType = StreamType.stdout):
        """
        Dump the standard stream.

        Args:
            stream_type (StreamType): The type of the stream to dump. Default is stdout.
        
        Short name: ds
        
        """
        await self.send_info(self.debugger.get_stdstream(stream_type))


    async def create_symbolic_file(self, name:str, content:str|None=None, size:int=0):
        """
        Create a symbolic file with name and size.

        Args:
            name (str): Name of the file
            content (str): Content of the file. Default is None. If content starts with $sym.SYM, the content is replaced with the symbol named SYM.
            size (int): Size of the file. Default is 0.
        
        Short name: cs
        
        """
        c = content
        if content is not None:
            if content.startswith("$"):
                t,s = content.split(".", 1)
                if t == "$sym":
                    c = self.debugger.get_symbol(content)
                    if c is None:
                        raise DebuggerCommandError(f"Symbol {content} not found.")
                    elif isinstance(c, claripy.ast.FP):
                        raise DebuggerCommandError("Symbol cannot be a floating point value.")
                else:
                    raise ValueError("Invalid content. Use $sym.")
        self.debugger.create_symbolic_file(name, c, size)
        await self.send_info(f"Symbolic file {name} created.")