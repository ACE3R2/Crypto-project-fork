

class KeySuite():
    def __init__(self, dh_key, dh_p, hmac = None, sdes = None, paillier_p = None, paillier_q = None, paillier_selfn = None, paillier_selfg = None, paillier_othern = None, paillier_otherg = None):
        self.diffie_hellman_private_key = dh_key
        self.diffie_hellman_public_p = dh_p
        self.hmac_symmetric_key = hmac
        self.sdes_symmetric_key = sdes
        self.paillier_private_p = paillier_p
        self.paillier_private_q = paillier_q
        if paillier_selfn == None and paillier_p != None and paillier_q != None:
            self.paillier_public_n = paillier_p * paillier_q
        else:
            self.paillier_public_n = paillier_selfn
        self.paillier_public_g = paillier_selfg
        self.paillier_public_other_n = paillier_othern
        self.paillier_public_other_g = paillier_otherg
        
        
    def session_key_update(self, symmetric_key):
        self.hmac_symmetric_key = symmetric_key & (2**512 - 1)
        self.sdes_symmetric_key = symmetric_key & (2**10 - 1)