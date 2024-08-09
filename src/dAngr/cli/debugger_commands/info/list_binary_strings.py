from ..base import BaseCommand

class ListBinaryStringsCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.optional_args = [("min_length",int, "Minimal length of the strings to search for")]
        self.info = "List the strings in a binary."
        self.short_cmd_name = "lbstr"

    async def execute(self, min_length=4): # type: ignore
        strings = self.debugger.get_binary_string_constants(min_length=min_length)
        return f"\taddress\tvalue\n{"\n".join([f"{s[0]}\t{s[1]}" for s in strings])}"
