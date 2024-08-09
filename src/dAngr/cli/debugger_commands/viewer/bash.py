
from dAngr.cli.debugger_commands.base import BaseCommand


class BashCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.arg_specs = [
            ('command', str, 'command to execute in shell')
        ]
        self.info = "execute commands in shell."
        self.short_cmd_name = "%"
        
    async def execute(self, command):
        # execute system command and return output
        import subprocess
        try:
            output = subprocess.check_output(command, shell=True)
            await self.send_result(output.decode())
        except subprocess.CalledProcessError as e:
            pass # error already output
        except Exception as e:
            await self.send_error(f"Error: {e}")


