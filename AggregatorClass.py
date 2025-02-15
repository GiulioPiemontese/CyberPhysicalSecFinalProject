import random
import hashlib
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

PRIME = 97

class AGGREGATOR:
    def __init__(self, id, provers, owner):
        self.id = id
        self.provers = provers
        self.owner = owner
        self.children = []
        self.alphas = []
        
    
    
    def set_children(self, children):
        self.children = children
    

    
    '''This is the method that only the root performs since only the root verifies the Ch'''
    def send_att_req(self, Ch):
        if self.VerifyChallenge(Ch):
            
            self.alphas = self.forward(Ch)
            
            return self.alphas
        else:
            print("Attestation Request Rejected.")
            
            return 0
        
    
    '''Method that forward the req from root to the children'''    
    def forward(self, Ch):
        self.alphas = []

        # Forward the challenge to children and collect their responses
        for child in self.children:
            alpha_child = child.forward(Ch)  # Recursively call forward()

            # Only append if the response is from a prover (no further children)
            if not child.children:
                self.alphas.append({"Device": child, "alpha": alpha_child})

            # If the response comes from an aggregator, merge it directly (avoid nesting)
            elif isinstance(alpha_child, list):  
                self.alphas.extend(alpha_child)

        # Aggregate responses received only from provers
        alpha_1 = self.aggregateResponse(self.alphas)

        return alpha_1


    def aggregateResponse(self, alphas):
        aggregated_alpha = []

        for alpha in alphas:
            if alpha:  # Ensure valid entries
                aggregated_alpha.append({"Device": alpha["Device"], "alpha": alpha["alpha"]})

        #if aggregated_alpha:
        #    print(f"Aggregation by {self}: ", aggregated_alpha)

        return aggregated_alpha if aggregated_alpha else None
    
    
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
        return f"Aggregator{self.id}"