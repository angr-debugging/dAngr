from ..base import BaseCommand

class ListPathHistoryCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Get the address of previously executed basic blocks."

    async def execute(self): 
        """List the history of the current execution path."""
        #TODO: check why it is not working
        paths = self.debugger.list_path_history()
        
        
        return "Path History: {paths}"

