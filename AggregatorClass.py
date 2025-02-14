import random
import hashlib
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

PRIME = 23

class AGGREGATOR:
    def __init__(self, id, provers, owner):
        self.id = id
        self.provers = provers
        self.owner = owner
        self.children = []
        self.alphas = []
        
        # Generate RSA Key Pair (in variables)
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Import keys directly from variables
        self.sk_a = RSA.import_key(private_key)
        self.pk_a = RSA.import_key(public_key)

    
    
    
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
        
        # forwarding the challenger to the neighbour
        for child in self.children:
            alpha_child = child.forward(Ch)
            self.alphas.append(alpha_child)
            
        N = random.randint(1, 10)
            
        T = Ch["T"]
            
        c_l = T["c_l"]
        v_l = T["v_l"]
        
        H = T["H"]
        h_g = hashlib.sha256("".join(H).encode()).hexdigest()   # TODO: don't know if it should be the getSoftConf like provers, for now lets do this
            
        # M <- h_g|N|c_l|v_l
        M = f"{h_g}{N}{c_l}{v_l}".encode()
            
        # alpha_1 = self.Sign(M) TODO: construct the right Sign method for aggregators
        alpha_1 = M
        
        alpha_1 = self.aggregateResponse(alpha_1, self.alphas, M)
            
        return alpha_1
    
    
    ''' 
    On input two aggregate signatures alpha1 , alpha2 and the default message M , the signature
    aggregation algorithm AggSig outputs a new aggregate signature
    alpha that includes all signatures in alpha1 and alpha2 
    '''
    def aggregateResponse(self, alpha_1, alphas, M):        
        # alpha_1 <- AggSign(alpha_1, alpha_i, M)
        aggregated_alpha = ""
        for alpha in alphas:
            aggregated_alpha += f"{alpha}" # lets consider it as concatenation at the moment
        
        aggregated_alpha += alpha_1 # TODO: alpha_1 is not a string, correct it
        
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
        return f"Aggregator{self.id}"