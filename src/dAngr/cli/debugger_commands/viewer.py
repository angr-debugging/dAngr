
from typing import cast
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.cli.less_view import Less


class ViewerCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)


    async def less(self):
        """
        View previously retrieved output in a scrollable pane.

        Short name: less
        """
        await Less().show_less(cast(CliConnection,self.debugger.conn).output)

    async def print(self, text:str):
        """
        Print a text.

        Args:
            text (str): Text to print.

        Short name: pr
        """
        await self.send_result(text)
    
    async def history(self, n:int=10):
        """
        Print the last n commands.

        Args:
            n (int): Number of commands to print. Default is 10.

        Short name: h
        """
        # print last n commands
        history = cast(CliConnection,self.debugger.conn).history
        for i in range(1, n+1):
            try:
                index = len(history) - i
                hs = history[-i]
                if not hs:
                    continue
                h = "\n".join([str(s) for s in hs[0] if s])
                #send first 70 chars of h
                await self.send_result(f"${index}: {h[:70]}")
            except IndexError:
                break
    async def clear_history(self):
        """
        Clear the command history.

        Short name: ch
        """
        cast(CliConnection,self.debugger.conn).clear_history()
        await self.send_info("Command history cleared.")