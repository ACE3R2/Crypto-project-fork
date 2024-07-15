
from mac import MAC

# Gives everything the same MAC
class NonMAC():
    def byte_return_length(self):
        return 1
    
    def get_mac(self, message):
        return 1