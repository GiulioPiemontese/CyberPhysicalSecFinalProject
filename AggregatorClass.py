import random
import hashlib
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5

PRIME = 7 #23

class AGGREGATOR:
    def __init__(self, provers, owner):
        self.provers = provers
        self.owner = owner
        self.children = []
        self.alphas = []
    
    def set_children(self, children):
        self.children = children
    
    def send_att_req(self, Ch):
        if self.VerifyChallenge(Ch):
            if self.children == []:
                return 0
            # forwarding the challenger to the neighbour
            for child in self.children:
                self.alphas.append(child.send_att_req(Ch))
            
            N = random.randint(1, PRIME - 1)
            
            T = Ch["T"]
            
            c_l = T["c_l"]
            v_l = T["v_l"]
            
            # M <- h_g|N|c_l|v_l
            M = f"{self.h_g}{N}{c_l}{v_l}"
            
            # TODO: but aggregators doesn't have any sk to make sign...
            alpha_1 = self.Sign(M)
            
            alpha_1 = self.aggregateResponse(alpha_1, self.alphas, M)
            
            return alpha_1
        
        else:
            print("Attestation Request Rejected.")
            return 0
        
    def aggregateResponse(self, alpha_1, alphas, M):        
        # alpha_1 <- AggSign(alpha_1, alpha_i, M)
        aggregated_alpha = alpha_1
        for alpha in alphas:
            aggregated_alpha += f"|{alpha}"
        
        return aggregated_alpha
        
    def Sign(self, M):
        return pow(M, self.sk, PRIME)# TODO: but aggregators doesn't have any sk to make sign...
        
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
        return f"Aggregator"