
import claripy
from dAngr.exceptions import DebuggerCommandError
from dAngr.utils.utils import StreamType, convert_argument
from .base import BaseCommand

class FileCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    async def dump_stdstream(self, stream_type: StreamType = StreamType.stdout):
        """
        Dump the standard stream.

        Args:
            stream_type (StreamType): The type of the stream to dump. Default is stdout.
        
        Short name: ds
        
        """
        return self.debugger.get_stdstream(stream_type)


    async def create_symbolic_file(self, name:str, content:str|None=None, size:int|None=None):
        """
        Create a symbolic file with name and size.

        Args:
            name (str): Name of the file
            content (str): Content of the file. Default is None. If content starts with $sym.SYM, the content is replaced with the symbol named SYM.
            size (int|None): Size of the file. Default is None.
        
        Short name: cs
        
        """
        if content is not None:
            c = self.debugger.render_argument(content)
            if isinstance(c, claripy.ast.FP):
                raise DebuggerCommandError("Cannot create symbolic file with floating point content.")
        self.debugger.create_symbolic_file(name, c, size) # type: ignore
        await self.send_info(f"Symbolic file {name} created.")