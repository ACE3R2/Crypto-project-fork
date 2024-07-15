import math
import random


class Paillier:
    def __init__(self, n, g, p=None, q=None):
        # Public
        if p is not None and q is not None:
            assert (n == p * q)
        self.n = n
        self.g = g

        # Private
        self.p = p
        self.q = q
        if p is not None and q is not None:
            self.lambda_n = self.lcm(p-1, q-1)
            self.u = pow(self.L(pow(g, self.lambda_n, n ** 2)), -1, n)
        else:
            self.lambda_n = None
            self.u = None

            
    def __init__(self, key_suite):
        self.p = key_suite.paillier_private_p
        self.q = key_suite.paillier_private_q
        self.selfn = key_suite.paillier_public_n
        self.selfg = key_suite.paillier_public_g
        self.othern = key_suite.paillier_public_other_n
        self.otherg = key_suite.paillier_public_other_g
        self.lambda_n = self.lcm(self.p-1, self.q-1)
        self.n = self.selfn
        self.g = self.selfg
        self.u = pow(self.L(pow(self.g, self.lambda_n, self.n ** 2)), -1, self.n)
        
        


    def lcm(self, a, b):
        return abs(a * b) // math.gcd(a, b)

    def L(self, x):
        return ((x - 1) % (self.n ** 2)) // self.n

    def get_public_key(self):
        return self.n, self.g

    def encrypt(self, msg, r):
        emsg = (pow(self.g, msg, self.n ** 2) * pow(r, self.n, self.n ** 2)) % self.n ** 2
        return emsg

    def decrypt(self, emsg):
        if self.p is None or self.q is None or self.u is None:
            raise Exception('Private key is not known')
        msg = (self.L(pow(emsg, self.lambda_n, self.n ** 2)) * self.u) % self.n
        return msg
        
        
    def encrypt_all(self, message):
        self.n = self.othern
        self.g = self.otherg
        r = 0
        while math.gcd(r,(self.n*self.n)) > 1:
            r = random.randrange(0,self.n)
        return self.encrypt(message, r)
        
    def decrypt_all(self, message):
        self.n = self.selfn
        self.g = self.selfg
        return self.decrypt(message)

if __name__ == "__main__":
    private_paillier = Paillier(126869, 6497955158, 293, 433)
    public_key = private_paillier.get_public_key()
    public_paillier = Paillier(*public_key)
    m = 280991720293
    c = public_paillier.encrypt(m, 12)
    dm = private_paillier.decrypt(c)
    print(m)
    print(c)
    print(dm)
