
from typing import cast
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.cli.less_view import Less


class ViewerCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

        
    async def bash(self, command:str):
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
            await self.send_result(output.decode())
        except subprocess.CalledProcessError as e:
            pass # error already output
        except Exception as e:
            await self.send_error(f"Error: {e}")

    async def less(self):
        """
        View previously retrieved output in a scrollable pane.

        Short name: less
        """
        await Less().show_less(cast(CliConnection,self.debugger.conn).output)
