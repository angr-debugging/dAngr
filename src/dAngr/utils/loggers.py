#create a logger that gets lambda functions as input and depending on DEBUG level, logs the output

# The logger should have the following methods:
# - debug
# - info
# - warning
# - error
import logging
from typing import Callable

class AsyncLogger(logging.Logger):
    def __init__(self, name):
        super().__init__(name)

    def debug(self, msg, *args, **kwargs):
        if isinstance(msg, Callable):
            if self.level == logging.DEBUG:
                super().debug(msg(), args, **kwargs)
        else:
            super().debug(msg, *args, **kwargs)
    def info(self, msg, *args, **kwargs):
        if isinstance(msg, Callable):
            if self.level in [logging.DEBUG, logging.INFO]:
                super().info(msg(), *args, **kwargs)
        else:
            super().info(msg, *args, **kwargs)
    def warning(self, msg, *args, **kwargs):
        if isinstance(msg, Callable):
            if self.level == [logging.DEBUG, logging.INFO, logging.WARNING]:
                super().warning(msg(), *args, **kwargs)
        else:
            super().warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        if isinstance(msg, Callable):
            if self.level in [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]:
                super().error(msg(), *args, **kwargs)
        else:
            super().error(msg, *args, **kwargs)


class LogConfig:
    level_to_str = {
            logging.DEBUG: "DEBUG",
            logging.INFO: "INFO",
            logging.WARNING: "WARNING",
            logging.ERROR: "ERROR",
            logging.CRITICAL: "CRITICAL",
            logging.NOTSET : "NOTSET"
        }
    def __init__(self, default_level: int):
        #set default level
        logging.setLoggerClass(AsyncLogger)
        logging.basicConfig(level=default_level)
        self.settings_per_module = { 
            "angr": logging.ERROR, 
            "pyvex": logging.ERROR, 
            "claripy": logging.ERROR, 
            "cle": logging.ERROR
        }
        for module, level in self.settings_per_module.items():
            self.set_module(module, level)

    def set_module(self, module:str, level: str|int):
        if isinstance(level, str):
            if level not in self.level_to_str.values():
                raise ValueError(f"Invalid log level: {level}")
            level = next(k for k,v in self.level_to_str.items() if v == level)
        self.settings_per_module[module] = level
        logger = logging.getLogger(module)
        logger.setLevel(level)
    
    def list_modules_from_loggers(self):
        
        #retrieve all loggers and their levels as a string
        loggers = logging.Logger.manager.loggerDict
        result = []
        for logger in loggers:
            if isinstance(loggers[logger],logging.Logger):
                l = loggers[logger]
                result.append(f"{logger}: {self.level_to_str[l.level]}") # type: ignore
        #sort the result alfabetically, but put loggers starting with "dAngr" first
        result.sort(key=lambda x: x if x.startswith("dAngr") else f"zzz{x}")
        return result

dAngr_log_config = LogConfig(logging.ERROR)
# dAngr_log_config.set_module("angr", logging.DEBUG)


get_logger = logging.getLogger
