from cipher import Cipher


# Does not encrypt or decrypt the message
class NonCipher(Cipher):
    def encrypt_all(self, message):
        return message
    
    def decrypt_all(self, message):
        return message