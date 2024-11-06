from array import array
import logging

from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.cli.grammar.expressions import ReferenceObject
from dAngr.utils.utils import DataType, AngrType, AngrValueType, AngrExtendedType, Endness

from dAngr.utils.loggers import get_logger
log = get_logger(__name__)

class ToolCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    def python(self, code:str):
        """
        Execute a python code.

        Args:
            code (str): Python code to execute.

        Short name: !
        """
        try:
            #execute python code and send the result
            return eval(code)
        except Exception as e:
            self.send_error(f"Error: {e}")

    def bash(self, command:str):
        """
        Execute a command in shell.

        Args:
            command (str): Command to execute in shell. May contain spaces.

        Short name: %
        """
        # execute system command and return output
        import subprocess
        try:
            output = subprocess.check_output(command, shell=True)
            return output.decode()
        except subprocess.CalledProcessError as e:
            pass # error already output
        except Exception as e:
            self.send_error(f"Error: {e}")
    
    def get_value(self, ref:str|AngrType):
        """
        Get the value of a variable or symbol.

        Args:
            ref (str|AngrType): Name/ref of the variable or symbol.

        Short name: gv
        """
        return self.get_angr_value(ref)

    def cast_to(self, value:AngrType, dtype:DataType):
        """
        Convert value to a specific data type.

        Args:
            value (AngrType): Value or reference to value to convert.
            dtype (DataType): Data type to convert to.
        
        Short name: to
        
        """
        value = self.get_angr_value(value)
        assert isinstance(value, AngrType), f"Invalid value type {type(value)}"
        return self.debugger.cast_to(value, dtype)
    
    def to_bytes(self, value:AngrType):
        """
        Convert ref to bytes based on current state.

        Args:
            value (AngrType): value or reference to the object. If str then we check either a symbol name or a variable name.
        
        Short name: ctb
        
        """
        return self.cast_to(value, DataType.bytes)
    
    def to_int(self, value:AngrType, endness:Endness=Endness.DEFAULT):
        """
        Solve and get concrete symbol value as int based on current state.

        Args:
            value (AngrType): value or reference to the object. If str then we check either a symbol name or a variable name.
            endness (Endness): Endianness of the value. Default is BE.
        
        Short name: cti
        
        """
        value = self.get_angr_value(value)
        assert isinstance(value, AngrType), f"Invalid value type {type(value)}"
        return self.debugger.cast_to(value, DataType.int, endness=endness)
    
    def to_str(self, value:AngrValueType):
        """
        Convert symbol to a str.

        Args:
            value (AngrValueType): value or reference to the object. If str then we check either a symbol name or a variable name.
        
        Short name: cts
        
        """
        return self.cast_to(value, DataType.str)
    def to_hex(self, value:AngrValueType):
        """
        Convert symbol to a hex representation.

        Args:
            value (AngrValueType): value or reference to the object. If str then we check either a symbol name or a variable name.
        
        Short name: cth
        
        """
        return self.cast_to(value, DataType.hex)
    
    def to_bool(self, value:AngrValueType):
        """
        Solve and get concrete symbol value as bool based on current state.

        Args:
            value (AngrValueType): value or reference to the object. If str then we check either a symbol name or a variable name.
        
        Short name: ctB
        
        """
        return self.cast_to(value, DataType.bool)
    def len(self, value:list|array):
        """
        Get the length of the value object

        Args:
            value (list|array): Value object to get the length of.

        """
        return len(value) # type: ignore