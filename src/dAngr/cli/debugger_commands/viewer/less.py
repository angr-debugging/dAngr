from typing import cast
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.less_view import Less
from dAngr.cli.models import BasicBlock
from ..base import BaseCommand
from dAngr.exceptions.DebuggerCommandError import DebuggerCommandError

class LessCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "View last previous output."
        self.short_cmd_name = "less"
        
    async def execute(self):
        await Less().show_less(cast(CliConnection,self.debugger.conn).output)


