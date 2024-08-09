
import sys
from dAngr.angr_ext.debugger import Debugger
from dAngr.cli.debugger_commands import BaseCommand
from dAngr.cli.filters import StdStreamFilter
from dAngr.utils.utils import StreamType


class StreamFilterCommand(BaseCommand):
    def __init__(self, debugger:Debugger):
        super().__init__(debugger)
        self.arg_specs = [("text",str,"Text that must be in the stream")]
        self.optional_args = [("avoid",bool,"When instead of breaking you want to ignroe the basic block"),
                              ("add",bool,"Add or remove the stream filter from the list"), 
                              ("stream",StreamType,"Stream to filter (i.e., stdin/stdout/stderr). Default 'stdout'")]
        self.info = "Filter if stream contains text."

    async def execute(self, text:str, avoid:bool=False, add:bool = True, stream:StreamType=StreamType.stdout): # type: ignore
        #check if the functions exist
        list = self.debugger.exclusions if avoid else self.debugger.breakpoints
        if not add:
            list = [f for f in list if not isinstance(f, StdStreamFilter) or f.value != text]
        else:
            list.append(StdStreamFilter(stream.value, text))
        await self.send_info(f"Stream filter '{text}' {'added to' if add else 'removed from'} {'exclusions' if avoid else 'breakpoints'}.")