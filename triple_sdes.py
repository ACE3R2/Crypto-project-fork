from cipher import Cipher
from sdes import SDES


class TripleSDES(Cipher):
    def __init__(self):
        self.sdes = SDES(rounds=5)
        self.block_size = self.sdes.block_size
        self.key_size = self.sdes.key_size * 3
        
    def __init__(self, key_suite):
        self.sdes = SDES(key_suite, rounds=5)
        self.block_size = self.sdes.block_size
        self.key_size = self.sdes.key_size * 3



    def extract_3_keys(self, key):
        sub_key_size = self.key_size // 3
        keys = []
        for i in range(3):
            keys.append((key >> i*sub_key_size) & 2**sub_key_size-1)
        return keys

    def encrypt_block(self, plaintext, key):
        keys = self.extract_3_keys(key)
        c1 = self.sdes.encrypt_block(plaintext, keys[0])
        c2 = self.sdes.decrypt_block(c1, keys[1])
        c3 = self.sdes.encrypt_block(c2, keys[2])
        return c3

    def decrypt_block(self, ciphertext, key):
        keys = self.extract_3_keys(key)
        p1 = self.sdes.decrypt_block(ciphertext, keys[2])
        p2 = self.sdes.encrypt_block(p1, keys[1])
        p3 = self.sdes.decrypt_block(p2, keys[0])
        return p3

    def encrypt_msg(self, message, key):
        encrypted_message = ''
        for c in message:
            encrypted_message += chr(self.encrypt_block(ord(c), key))
        return encrypted_message

    def decrypt_msg(self, encrypted_message, key):
        decrypted_message = ''
        for c in encrypted_message:
            decrypted_message += chr(self.decrypt_block(ord(c), key))
        return decrypted_message
        
        
        
    
    
    def encrypt_all_blocks(self, plaintext, key):
        ctr = 0
        ciphertext = 0
        rounds = 0
        while plaintext > 0:
            plaintext_block = plaintext & (2**self.block_size - 1)
            encrypted_block = self.encrypt_block(plaintext_block, key)
            ciphertext = (encrypted_block << ctr) + ciphertext
            ctr += self.block_size
            plaintext = plaintext >> self.block_size
        return ciphertext
        
        
    def decrypt_all_blocks(self, ciphertext, key):
        ctr = 0
        plaintext = 0
        while ciphertext > 0:
            ciphertext_block = ciphertext & (2**self.block_size - 1)
            decrypted_block = self.decrypt_block(ciphertext_block, key)
            plaintext = (decrypted_block << ctr) + plaintext
            ctr += self.block_size
            ciphertext = ciphertext >> self.block_size
        return plaintext
        

    def encrypt_all(self, message):
        return self.encrypt_all_blocks(message, self.sdes.symkey)
    
    def decrypt_all(self, message):
        return self.decrypt_all_blocks(message, self.sdes.symkey)


if __name__ == "__main__":
    triple_sdes = TripleSDES()
    print('Encryption/Decryption test:')
    opt = int('00101000', 2)
    k = int('110001111010100101101000011011', 2)
    ct = triple_sdes.encrypt_block(opt, k)
    dpt = triple_sdes.decrypt_block(ct, k)
    print(f'Key: {bin(k)}')
    print(f'Original Plaintext: {bin(opt)}')
    print(f'Ciphertext: {bin(ct)}')
    print(f'Decrypted Plaintext: {bin(dpt)}')
    print('-' * 16)
    print('Encrypt message "crypto":')
    omsg = 'crypto'
    emsg = triple_sdes.encrypt_msg(omsg, k)
    dmsg = triple_sdes.decrypt_msg(emsg, k)
    print(f'Original message: {omsg}')
    print(f'Encrypted message: {emsg}')
    print(f'Encrypted message in binary: {" ".join([bin(ord(c))[2:].zfill(8) for c in emsg])}')
    print(f'Decrypted message: {dmsg}')
