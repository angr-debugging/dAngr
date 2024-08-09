from ...base import BaseCommand

class ListFiltersCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.optional_args = [("exclusions",bool,"If True, list the exclusions instead of the breakpoints.")]
        self.info = "List all breakpoints. If exclusions is set (default: False), list all exclusions instead."

    async def execute(self, exclusions:bool=False):
        list = self.debugger.exclusions if exclusions else self.debugger.breakpoints
        if len(list) == 0:
            await self.send_info(f'No {"exclusions" if exclusions else "breakpoints"} set.')
            return []
        return f'{"Exclusion" if exclusions else "Breakpoint" }(s): {",".join([f"[{i}] {b}" for i,b in enumerate(list)])}'
