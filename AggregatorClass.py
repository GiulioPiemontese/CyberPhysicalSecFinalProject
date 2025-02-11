from DeviceClass import DEVICE
import random
import hashlib
import time

PRIME = 23

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
        H = self.owner.getGoodConfigs()
        
        self.h_g = hashlib.sha256("".join(H).encode()).hexdigest()
        
        T = Ch["T"]
        
        t_exp = T["t_exp"]
        
        c_l, v_l = T["c_l"], T["v_l"]
        
        sigma_o = T["sigma_1"]
        
        msg = f"{self.h_g}{c_l}{v_l}{t_exp}"
        
        if (t_exp < time()) or (not(self.CheckCounter(c_l, v_l))):
            print("Aborted.")
            
            return False
        
        elif not(self.Verify(self.owner.pk_o, msg, sigma_o)) :
            print("Aborted.")
        
            return False
        
        return True
    
    def CheckCounter(self, c_l, v_l):
        pass    # TODO
    
    def Verify(self, pk_o, msg, sigma):
        if pow(msg, pk_o, PRIME) == sigma:
            return True
        
        else:
            return False
    
    def __repr__(self):
        return f"Aggregator"