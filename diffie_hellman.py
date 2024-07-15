from cipher import Cipher


class DiffieHellman(Cipher):

    def __init__(self, key_suite):
        self.private_key = key_suite.diffie_hellman_private_key
        self.p = key_suite.diffie_hellman_public_p



    # Technically not an encryption/decryption mechanic, since just constructing a shared key rather than the initial message
    def encrypt_all(self, message):
        return pow(message, self.private_key, self.p)
    
    # Decryption does not get the original message back but the new key
    def decrypt_all(self, message):
        return pow(message, self.private_key, self.p)
    