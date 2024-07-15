from cipher import Cipher


class SDES(Cipher):
    def __init__(self, rounds=2):
        self.block_size = 8
        self.half_block_size = int(self.block_size / 2)
        self.key_size = 10
        self.half_key_size = int(self.key_size / 2)
        self.rounds = rounds
        
        
    def __init__(self, key_suite, rounds=2):
        self.symkey = key_suite.sdes_symmetric_key
        self.block_size = 8
        self.half_block_size = int(self.block_size / 2)
        self.key_size = 10
        self.half_key_size = int(self.key_size / 2)
        self.rounds = rounds

    def permutation(self, value, positions, num_bits):
        result = 0
        for pos in positions:
            result = (result << 1) | ((value >> (num_bits-pos) & 1))
        return result

    def rotate_left(self, value, amt, num_bits):
        amt = amt % num_bits
        return ((value << amt) | (value >> (num_bits - amt))) & (2 ** num_bits - 1)

    def round_function(self, half_block, key):
        s0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
        s1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

        expanded = self.permutation(half_block, [4, 1, 2, 3, 2, 3, 4, 1], self.half_block_size)
        x = expanded ^ key
        lh = x >> self.half_block_size
        rh = x & (2 ** self.half_block_size - 1)
        lh = s0[self.permutation(lh, [1, 4], self.half_block_size)][self.permutation(lh, [2, 3], self.half_block_size)]
        rh = s1[self.permutation(rh, [1, 4], self.half_block_size)][self.permutation(rh, [2, 3], self.half_block_size)]
        result = (lh << 2) + rh
        result = self.permutation(result, [2, 4, 3, 1], self.half_block_size)
        return result

    def generate_key_schedule(self, initial_key):
        keys = []
        initial_key = self.permutation(initial_key, [3, 5, 2, 7, 4, 10, 1, 9, 8, 6], self.key_size)
        lh = initial_key >> self.half_key_size
        rh = initial_key & (2 ** self.half_key_size - 1)
        for i in range(self.rounds):
            lh = self.rotate_left(lh, i + 1, self.half_key_size)
            rh = self.rotate_left(rh, i + 1, self.half_key_size)
            keys.append(self.permutation((lh << self.half_key_size) + rh, [6, 3, 7, 4, 8, 5, 10, 9], self.key_size))
        return keys

    def feistel_cipher(self, input_text, keys):
        x = self.permutation(input_text, [2, 6, 3, 1, 4, 8, 5, 7], self.block_size)
        lh = x >> self.half_block_size
        rh = x & (2 ** self.half_block_size - 1)
        for key in keys:
            tmp = self.round_function(rh, key) ^ lh
            lh = rh
            rh = tmp

        lh, rh = rh, lh
        result = (lh << self.half_block_size) + rh
        result = self.permutation(result, [4, 1, 3, 5, 7, 2, 8, 6], self.block_size)
        return result

    def encrypt_block(self, plaintext, key):
        keys = self.generate_key_schedule(key)
        ciphertext = self.feistel_cipher(plaintext, keys)
        return ciphertext

    def decrypt_block(self, ciphertext, key):
        keys = self.generate_key_schedule(key)
        keys.reverse()
        plaintext = self.feistel_cipher(ciphertext, keys)
        return plaintext

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
        return self.encrypt_all_blocks(message, self.symkey)
    
    def decrypt_all(self, message):
        return self.decrypt_all_blocks(message, self.symkey)


if __name__ == "__main__":
    sdes = SDES(rounds=5)
    print('Encryption/Decryption test:')
    opt = int('00101000', 2)
    k = int('1100011110', 2)
    ct = sdes.encrypt_block(opt, k)
    dpt = sdes.decrypt_block(ct, k)
    print(f'Key: {bin(k)}')
    print(f'Original Plaintext: {bin(opt)}')
    print(f'Ciphertext: {bin(ct)}')
    print(f'Decrypted Plaintext: {bin(dpt)}')
    print('-' * 16)
    print('Encrypt message "crypto":')
    omsg = 'crypto'
    emsg = sdes.encrypt_msg(omsg, k)
    dmsg = sdes.decrypt_msg(emsg, k)
    print(f'Original message: {omsg}')
    print(f'Encrypted message: {emsg}')
    print(f'Encrypted message in binary: {" ".join([bin(ord(c))[2:].zfill(8) for c in emsg])}')
    print(f'Decrypted message: {dmsg}')

