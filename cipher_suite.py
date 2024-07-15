from hmac import HMAC
from triple_sdes import TripleSDES
from sdes import SDES
from diffie_hellman import DiffieHellman
from noncipher import NonCipher
from nonmac import NonMAC
from paillier import Paillier
from sha1 import SHA1Hasher
from quickmac import QuickMAC

import math


class CipherSuite():
    def __init__(self, keysuite):
        self.key_suite = keysuite
        self.mac = NonMAC()
        self.cipher = DiffieHellman(self.key_suite)
        self.codes = ["Done", "SDES", "TripleSDES", "Paillier", "NonCipher", "QuickMAC", "HMAC", "NonMAC"]
        
        
    def cipher_system_to_code(self, name):
        if name in self.codes:
            return self.codes.index(name)
        # dummy value, not associated with any cipher
        return 63
        
     
    # Change cryptosystem used to encode messages
    def switch_ciphersystem(self, code):
        if code == 1:
            self.cipher = SDES(self.key_suite)
        elif code == 2:
            self.cipher = TripleSDES(self.key_suite)
        elif code == 3:
            self.cipher = Paillier(self.key_suite)
        elif code == 4:
            self.cipher = NonCipher()
        elif code == 5:
            self.mac = QuickMAC()
        elif code == 6:
            self.mac = HMAC(self.key_suite)
        elif code == 7:
            self.mac = NonMAC()
        else:
            return -1
        return 0
    
    def received_session_key(self, key):
        self.key_suite.session_key_update(key)
        # Do not want to assume client capabilities so switch to unencoded
        # Not a big deal because this only lasts for the duration that client chooses ciphersystems (which is immediately after this 
        # is called), and the choice of ciphersystem is generally public information anyway
        self.cipher = NonCipher()
    
        
    def encode_message(self, msg):
        return self.cipher.encrypt_all(msg)
        
        
    def decode_message(self, msg):
        return self.cipher.decrypt_all(msg)
    
    
    def add_mac_to_message(self, msg):
        right_padded_msg = msg << (8*self.mac.byte_return_length())
        msg_mac = self.mac.get_mac(msg)
        return right_padded_msg + msg_mac
        
    def add_mac_to_different_message(self, mac_msg, appd_msg):
        right_padded_msg = appd_msg << (8*self.mac.byte_return_length())
        msg_mac = self.mac.get_mac(mac_msg)
        return right_padded_msg + msg_mac
    
    
    def verify_message(self, msg_text, mac_msg):
        mac_text = self.mac.get_mac(msg_text)
        return mac_text == mac_msg
    
    
    def separate_mac(self, full_msg):
        mac_byte_length = self.mac.byte_return_length()
        mac_bit_length = mac_byte_length * 8
        actual_message = full_msg >> mac_bit_length
        mac_message = full_msg & (2**mac_bit_length - 1)
        return actual_message, mac_message
        
     # Encrypts the message, then adds the mac (of the original) to the message, then sends through the socket
    def encode_and_send(self, message, socket):
        encrypted_message = self.encode_message(message)
        appended_encrypted_message = self.add_mac_to_different_message(message, encrypted_message)
        socket.send_full_message(appended_encrypted_message)
        return True
        
     # Receives the message, then verifies the mac, then decrypts the message, then returns the message
     # If something goes wrong (other side disconnects or mac does not verify), return < 0
    def receive_and_decode(self, socket):
        message = socket.receive_full_message()
        if message < 0:
            return -1
        message_text, message_mac = self.separate_mac(message)
        decrypted_message_text = self.decode_message(message_text)
        check = self.verify_message(decrypted_message_text, message_mac)
        if not check:
            return -2
        return decrypted_message_text
        