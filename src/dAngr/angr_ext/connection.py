
from abc import abstractmethod


class Connection:
    def __init__(self):
        pass
    
    @abstractmethod
    async def send_result(self, data, style=None)->None:
        raise NotImplementedError
    
    @abstractmethod
    async def send_info(self, data, style=None)->None:
        raise NotImplementedError

    @abstractmethod
    async def send_output(self, data, style=None)->None:
        raise NotImplementedError

    @abstractmethod
    async def send_error(self, data, style=None)->None:
        raise NotImplementedError
    
    @abstractmethod
    async def send_warning(self, data, style=None)->None:
        raise NotImplementedError
