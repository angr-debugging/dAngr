
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands.execution.continue_ import ContinueCommand
from dAngr.exceptions import DebuggerCommandError


class RunCommand(ContinueCommand):
    def __init__(self, debugger:Debugger
                    ):
            super().__init__(debugger)
            self.info = "Start the execution. Same as continue."
            self.short_cmd_name = "c"
    pass

