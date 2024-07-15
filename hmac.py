from mac import MAC
from sha1 import SHA1Hasher

class HMAC(MAC):
    def __init__(self, key_suite):
        self.symkey = key_suite.hmac_symmetric_key
        self.sha_hasher = SHA1Hasher()


    def byte_return_length(self):
        return 20

    # Pads right by amt bits
    def pad_right_fixed_amt(self, value, amt):
        return value << amt

    def concat(self, val1, val2):
        val2_len = len(format(val2,'b'))
        return self.pad_right_fixed_amt(val1, val2_len) + val2

    # Pads right enough to end with end_len length in bits
    # Undefined if len(val) > end_len
    def pad_right(self, value, end_len):
        curr_len = len(format(value,'b'))
        return self.pad_right_fixed_amt(value, end_len - curr_len)


    def get_mac(self, message):
        return self.get_hmac(message, self.symkey, self.sha_hasher.get_hash)
        
        
    #def get_mac(self, msg, key):
    #    sha1_hasher = SHA1Hasher()
    #    return self.get_hmac(msg, key, sha1_hasher.get_hash)
        
        
    def get_hmac(self, msg, key, hashfunc):
        block_len = 64
        opad_strval = "36" * block_len
        ipad_strval = "5c" * block_len
        opad = int(opad_strval, 16)
        ipad = int(ipad_strval, 16)
        
        padded_key = self.pad_right(key, block_len * 8)
        outer_join = padded_key ^ opad
        second_join = self.concat(outer_join, msg)
        second_hash = hashfunc(second_join)
        inner_join = padded_key ^ ipad
        final_join = self.concat(inner_join, second_hash)
        final_hash = hashfunc(final_join)
        
        return final_hash
        
        
if __name__ == "__main__":
    hmac_maker = HMAC()
    key = int("12345678901234567890", 16)
    msg_int = int(b'Hello World!'.hex(),16)
    msg_mac = hmac_maker.get_mac(msg_int, key)
    print(msg_mac)
    msg_int = int(b'Nevermind'.hex(),16)
    msg_mac = hmac_maker.get_mac(msg_int, key)
    print(msg_mac)