
from abc import abstractmethod


class Connection:
    def __init__(self):
        pass
    
    @abstractmethod
    def send_result(self, data,newline=True, style=None)->None:
        raise NotImplementedError
    
    @abstractmethod
    def send_info(self, data, style=None)->None:
        raise NotImplementedError

    @abstractmethod
    def send_output(self, data, style=None)->None:
        raise NotImplementedError

    @abstractmethod
    def send_error(self, data, style=None)->None:
        raise NotImplementedError
    
    @abstractmethod
    def send_warning(self, data, style=None)->None:
        raise NotImplementedError
