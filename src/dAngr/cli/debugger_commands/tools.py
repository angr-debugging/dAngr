from array import array

from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.exceptions import DebuggerCommandError
from dAngr.utils.utils import DataType, AngrType, AngrValueType, Endness

#import Bool from claripy
from claripy.ast import Bool

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
            return exec(code)
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
    def len(self, value:str|list|array|bytes):
        """
        Get the length of the value object

        Args:
            value (str|list|array|bytes): Value object to get the length of.

        """
        return len(value) # type: ignore
    
    def strip(self, value:str|bytes, chars:str|bytes|None = None):
        """
        Strip the head and tail of the string or bytes

        Args:
            value (str|bytes): Value to strip.
            chars (str|bytes|None): chars to strip. Default None = empty string. 

        """

        #extract \xDD chars

        v = self.debugger.cast_to(value, DataType.bytes) if isinstance(value,str) else value
        c = self.debugger.cast_to(chars, DataType.bytes) if isinstance(chars, str) else chars
        if v and isinstance(v, bytes):
            return v.strip(c)
        else:
            raise DebuggerCommandError("Failed to convert value")
        
    def lstrip(self, value:str|bytes, chars:str|bytes|None = None):
        """
        Strip the head of the string or bytes

        Args:
            value (str|bytes): Value to strip.
            chars (str|bytes|None): chars to strip. Default None = empty string. 

        """

        #extract \xDD chars

        v = self.debugger.cast_to(value, DataType.bytes) if isinstance(value,str) else value
        c = self.debugger.cast_to(chars, DataType.bytes) if isinstance(chars, str) else chars
        if v and isinstance(v, bytes):
            return v.lstrip(c)
        else:
            raise DebuggerCommandError("Failed to convert value")
    
    def rstrip(self, value:str|bytes, chars:str|bytes|None = None):
        """
        Strip the tail of the string or bytes

        Args:
            value (str|bytes): Value to strip.
            chars (str|bytes|None): chars to strip. Default None = empty string. 

        """

        #extract \xDD chars

        v = self.debugger.cast_to(value, DataType.bytes) if isinstance(value,str) else value
        c = self.debugger.cast_to(chars, DataType.bytes) if isinstance(chars, str) else chars
        if v and isinstance(v, bytes):
            return v.rstrip(c)
        else:
            raise DebuggerCommandError("Failed to convert value")
        
    def append(self, value:list, object):
        """
        Append the tail of the value

        Args:
            value (list): Value append to.
            object (): object to append to value

        """
        if isinstance(value, list):
             value.append(object)
             return value
        else:
            raise DebuggerCommandError("Invalid format")
    
    def sort(self, value:list, reverse=False):
        """
        Sort the value

        Args:
            value (list): List to sort.

        """
        if isinstance(value, list):
             sorted(value, reverse=reverse)
             return value
        else:
            raise DebuggerCommandError("Invalid format")

    def extend(self, value:list, iterable):
        """
        Extend the tail of the value

        Args:
            value (list): Value extend to.
            iterable (): iterable to extend to value

        """
        if isinstance(value, list):
             value.extend(iterable)
             return value
        else:
            raise DebuggerCommandError("Invalid format")
        
    def assertion(self, condition:bool|Bool, message:str="Assertion failed"):
        """
        Assert a condition.

        Args:
            condition (bool): Condition to assert.
            message (str): Message to display if assertion fails.

        Raises:
            DebuggerCommandError: If the assertion fails.

        Short name: assert
        """
        if(isinstance(condition, Bool) and not condition.is_true()):
            raise DebuggerCommandError(message)
        if(isinstance(condition, bool) and not condition):
            raise DebuggerCommandError(message)
        
    def export_state(self, filepath:str):
        """
        Export the current state to a file.

        Args:
            filepath (str): Path to the file where the state will be exported.

        Short name: expstate
        """
        self.debugger.export_state(filepath)
        self.send_info(f"State exported to {filepath}.")

    def export_project(self, filepath:str):
        """
        Export the current project to a file.

        Args:
            filepath (str): Path to the file where the project will be exported.

        Short name: expproj
        """
        self.debugger.export_project(filepath)
        self.send_info(f"Project exported to {filepath}.")

    def import_project(self, filepath:str):
        """
        Import a project from a file.

        Args:
            filepath (str): Path to the file from which the project will be imported.

        Short name: impproj
        """
        self.debugger.import_project(filepath)
        self.send_info(f"Project imported from {filepath}.")


        