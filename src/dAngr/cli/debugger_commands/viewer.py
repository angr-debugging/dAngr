
from typing import cast
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.angr_ext.expressions import ReferenceObject
from dAngr.cli.less_view import Less


class ViewerCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)


    def less(self):
        """
        View previously retrieved output in a scrollable pane.

        Short name: less
        """
        out = cast(CliConnection,self.debugger.conn).output
        if not out and len(cast(CliConnection,self.debugger.conn).history) > 1:
            out = cast(CliConnection,self.debugger.conn).history[-2]

        Less().show_less(out)

    def print(self, text:object|ReferenceObject):
        """
        Print a text.

        Args:
            text (object|ReferenceObject): Text or object content to print.

        Short name: pr
        """
        self.send_result(str(text), False)
        
    def println(self, text:object|ReferenceObject = ""):
        """
        Print a text, ending with a newline

        Args:
            text (object|ReferenceObject): Text or object content to print.

        Short name: prnl
        """
        self.send_result(str(text), True)
    
    def history(self, n:int=10):
        """
        Print the last n commands.

        Args:
            n (int): Number of commands to print. Default is 10.

        Short name: h
        """
        # print last n commands
        return cast(CliConnection,self.debugger.conn).history
        for i in range(1, n+1):
            try:
                index = len(history) - i
                hs = history[-i]
                if not hs:
                    continue
                h = "\n".join([str(s) for s in hs[0] if s])
                #send first 70 chars of h
                self.send_result(f"${index}: {h[:70]}")
            except IndexError:
                break
    def clear_history(self):
        """
        Clear the command history.

        Short name: ch
        """
        cast(CliConnection,self.debugger.conn).clear_history()
        self.send_info("Command history cleared.")