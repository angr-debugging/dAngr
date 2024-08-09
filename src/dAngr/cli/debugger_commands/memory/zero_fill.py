from ..base import BaseCommand

class ZeroFillCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Enable or disable to fill memory and registers with zero values."
        self.optional_args = [("enable", bool, "Enable zero fill if True, disable if False. Default is True.")]

    async def execute(self, enable=True):
        await self.debugger.zero_fill(enable)
        await self.send_info( f"Zero fill {'enabled' if enable else 'disabled'}.")
