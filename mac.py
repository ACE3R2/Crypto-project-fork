from abc import ABC, abstractmethod


class MAC(ABC):
    @abstractmethod
    def get_mac(self, message):
        pass
        
    @abstractmethod
    def byte_return_length(self):
        pass