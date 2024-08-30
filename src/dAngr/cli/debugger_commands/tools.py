from dAngr.cli.debugger_commands.base import BaseCommand


class ToolCommands(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)

    async def python(self, code:str):
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
            await self.send_error(f"Error: {e}")

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
            return output.decode()
        except subprocess.CalledProcessError as e:
            pass # error already output
        except Exception as e:
            await self.send_error(f"Error: {e}")