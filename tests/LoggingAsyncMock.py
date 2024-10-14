

import asyncio
from dAngr.utils.loggers import dAngr_log_config, get_logger
dAngr_log_config.set_module("dAngr", "DEBUG")
from unittest.mock import AsyncMock


class LoggingAsyncMock(AsyncMock):
    def __init__(self, type:str, *args, **kwargs):
        # Initialize AsyncMock and store mock name (if provided)
        super().__init__(*args, **kwargs)
        self.type = type
        self.log = get_logger("test")

    def _log_call(self, *args, **kwargs):
        # Log the function call
        if kwargs:
            self.log.debug(f"{self.type}: {" ".join([str(a) for a in args])} -- {kwargs}")
        else:
            self.log.debug(f"{self.type}: {" ".join([str(a) for a in args])}")

    async def _mock_call(self, *args, **kwargs):
        # Log the call before calling the original AsyncMock
        self._log_call(*args, **kwargs)
        return await super()._mock_call(*args, **kwargs)  # Delegate to AsyncMock
