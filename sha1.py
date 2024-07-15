from hasher import Hasher


class SHA1Hasher(Hasher):
    def rotate_left(self, value, amt, num_bits):
        amt = amt % num_bits
        return ((value << amt) | (value >> (num_bits - amt))) & (2 ** num_bits - 1)

    def bitwise_not(self, n, num_bits):
        return (1 << num_bits) - 1 - n

    def get_chunks(self, big_input):
        """
        :param big_input: Input to break into chunks
        :return: list of 512-bit integer chunks
        """
        chunks = []

        if type(big_input) is str:
            ml = len(big_input) * 8
            padding_len = 65 + abs((ml + 65) % -512)
            padding = (1 << (padding_len-1)) + ml
            assert((ml + padding_len) % 512 == 0)
            for i in range(0, padding_len, 8):
                big_input += chr(((padding >> i) & (2**8-1)))
            str_chunks = [big_input[i:i+64] for i in range(0, len(big_input), 64)]
            for s in str_chunks:
                chunk_val = 0
                for i in range(64):
                    chunk_val += ord(s[i]) << ((64-i-1) * 8)
                chunks.append(chunk_val)

        else:
            ml = len(bin(big_input))-2
            padding_len = 65 + abs((ml + 65) % -512)
            padding = (1 << (padding_len-1)) + ml
            assert ((ml + padding_len) % 512 == 0)
            big_input = (big_input << padding_len) + padding
            for i in range(0, ml+padding_len, 512):
                chunk_val = (big_input >> i) & (2**512-1)
                chunks.append(chunk_val)

        return chunks

    def get_hash(self, hash_input):
        """
        :param hash_input: Input to be hashed
        :return: 160-bit SHA1 hash
        Implementation based on https://en.wikipedia.org/wiki/SHA-1
        """
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0

        chunks = self.get_chunks(hash_input)
        for chunk in chunks:
            w = [(chunk >> i*32) & (2**32-1) for i in range(16)]

            for i in range(16, 80):
                w.append(self.rotate_left(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1, 32))

            assert(len(w) == 80)

            a = h0
            b = h1
            c = h2
            d = h3
            e = h4

            for i in range(80):
                if 0 <= i <= 19:
                    f = (b & c) | (self.bitwise_not(b, 32) & d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                tmp = self.rotate_left(a, 5, 32) + f + e + k + w[i]
                e = d
                d = c
                c = self.rotate_left(b, 30, 32)
                b = a
                a = tmp

            h0 = (h0 + a) & (2**32-1)
            h1 = (h1 + b) & (2**32-1)
            h2 = (h2 + c) & (2**32-1)
            h3 = (h3 + d) & (2**32-1)
            h4 = (h4 + e) & (2**32-1)

        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
        return hh


if __name__ == "__main__":
    sha1_hasher = SHA1Hasher()
    hash_result = sha1_hasher.get_hash("Hash this text")
    print(hex(hash_result))
    hash_result = sha1_hasher.get_hash("Hash this next")
    print(hex(hash_result))
    hash_result = sha1_hasher.get_hash(1)
    print(hex(hash_result))
    hash_result = sha1_hasher.get_hash(2)
    print(hex(hash_result))
    hash_result = sha1_hasher.get_hash(100)
    print(hex(hash_result))
