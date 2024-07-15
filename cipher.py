from abc import ABC, abstractmethod


class Cipher(ABC):
    @abstractmethod
    def encrypt_all(self, message):
        pass
        
        
    def decrypt_all(self, message):
        pass