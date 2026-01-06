
from dAngr.utils.utils import StreamType, SymBitVector, Variable
from .base import BaseCommand

class FileCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    def dump_stdstream(self, stream_type: StreamType = StreamType.stdout):
        """
        Dump the standard stream.

        Args:
            stream_type (StreamType): The type of the stream to dump. Default value is stdout. (other values stdin (0), stderr (2))
        
        Short name: ds
        
        """
        return self.debugger.get_stdstream(stream_type)


    def create_symbolic_file(self, name:str, content:str|SymBitVector|Variable|None=None, size:int|None=None):
        """
        Create a symbolic file with name and size.

        Args:
            name (str): Name of the file
            content (str|SymBitVector|Variable|None): Content of the file. Default is None. If content starts with $sym.SYM, the content is replaced with the symbol named SYM.
            size (int|None): Size of the file. Default is None.
        
        Short name: csf
        
        """
        c = None
        if not content is None:
            c = self.to_value(content)
        self.debugger.create_symbolic_file(name, c, size) # type: ignore
        self.send_info(f"Symbolic file {name} created.")