import hashlib
import time
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

PRIME = 23

class PROVER:
    def __init__(self, id):
        self.id = id
        self.sk = None
        self.pk = None
        self.cert = None
        self.owner = None
        self.M = "Default MSG"
        
    
        
    def receive_trust_env(self, key_pair, cert, owner):
        self.sk = key_pair[0]
        self.pk = key_pair[1]
        self.cert = cert
        self.owner = owner
        
    
    
    def get_id(self):
        return self.id
    
    
    
    # just the method called by aggregator to forward Ch that Create the alpha for response
    def forward(self, Ch):
        if self.VerifyChallenge(Ch):
            return self.CreateResponse(Ch)

        else:
            return 0
        
        
        
    # create the alpha to be sent back to the caller
    def CreateResponse(self, Ch):
        T = Ch["T"]
        
        c_l = T["c_l"]
        v_l = T["v_l"]
        
        N = Ch["N"]
        
        H = T["H"]
        
        h = self.getSoftConf()
    
        if h in H:
            h = hashlib.sha256("".join(h).encode()).hexdigest() # h <- h_g
        
        # msg1 = h|N|c_l|v_l
        msg = f"{h}{N}{c_l}{v_l}".encode()
        
        # Sign both messages using OAS: h|N|c_l|v_l and M
        msg1 = self.Sign(msg)
        msg2 = self.Sign(self.M.encode())        
        
        # alpha = Sign(sk; h|N|c_l|v_l, M) TODO: but i think that they are not concatenated but are returned as couple of msg
        alpha = f"{msg1}{msg2}".encode()
        
        return alpha
    
    
    def hash_to_G1(self, msg):
        """
        Hashes the message and maps it into the G1 group using modular reduction.
        """
        h = int(hashlib.sha256(msg).hexdigest(), 16)  # Convert hash to an integer
        return h % PRIME  # Reduce it into the finite field (G1)

    def Sign(self, msg):
        """
        Signs the message using OAS scheme
        """
        H_m = self.hash_to_G1(msg)  # Convert message to element in G1
        sign = pow(H_m, self.sk, PRIME)  # Compute signature in G1
        return sign
    
    
    
    def getSoftConf(self):
        conf = "conf1"
        
        return conf
    
    
    
    def VerifyChallenge(self, Ch):
        T = Ch["T"]
        
        H = T["H"]
        
        self.h_g = hashlib.sha256("".join(H).encode()).hexdigest()
        
        t_exp = T["t_exp"]
        
        c_l, v_l = T["c_l"], T["v_l"]
        
        sigma_o = T["sigma_1"]
        
        msg = f"{self.h_g}{c_l}{v_l}{t_exp}".encode()
        
        if (t_exp < int(time.time())) or (not(self.CheckCounter(c_l, v_l))):
            print("Aborted.")
            
            return False
        
        elif not(self.Verify(self.owner.generate_cert(0), msg, sigma_o)):
            print("Aborted.")
        
            return False
        
        return True



    def CheckCounter(self, c_l, v_l):
        return True    # TODO
    
    
    
    def Verify(self, pk_o, msg, sigma):
        """Verifies the signature"""
        try:
            if isinstance(pk_o, RSA.RsaKey):  
                cert_public_key = pk_o  # It's already an RSA key, no need to import
            else:
                cert_public_key = RSA.import_key(pk_o)
                        
            # Hash the message
            hashed_msg = SHA256.new(msg)

            # Verify the signature
            pkcs1_15.new(cert_public_key).verify(hashed_msg, sigma)
                    
            return True  # Signature is valid
        
        except (ValueError, TypeError):
            return False  # Signature verification failed

    
    
    def __repr__(self):
        return f"Prover{self.id}"
    
    
    
    def __str__(self):
        return f"Prover{self.id}:ID={self.id}, SK={self.sk}, PK={self.pk}"
    