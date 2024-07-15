from abc import ABC, abstractmethod


class Hasher(ABC):
    @abstractmethod
    def get_hash(self, msg):
        pass
