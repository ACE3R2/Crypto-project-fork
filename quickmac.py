from mac import MAC



class QuickMAC():
    def byte_return_length(self):
        return 16
        
    
    # Quick integer hash function - unkeyed
    def get_mac(self, message):
        x = message
        x = ((x >> 16) ^ x) * 0x45d9f3b;
        x = ((x >> 16) ^ x) * 0x45d9f3b;
        x = (x >> 16) ^ x;
        x = x % (2 ** (self.byte_return_length() * 8))
        return x


