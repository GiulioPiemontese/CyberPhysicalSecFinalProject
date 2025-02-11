from DeviceClass import DEVICE
import random
import hashlib
import json

PRIME = 23

class VERIFIER:
    def __init__(self, owner, aggregators):
        self.id = random.randint(1, PRIME)
        self.delta_t = 3600         # max expiration time
        self.sk_v = random.randint(1, PRIME - 1)
        self.pk_v = pow(owner.g2, self.sk_v, PRIME)
        self.aggregators = aggregators
        self.owner = owner
        
    
    def tokenReq(self):
        self.N_v = random.randint(1, 10)
        
        no_challenge = self.owner.get_nonce(self.N_v)
        
        sigma_v = self.create_signature(no_challenge)
        
        cert_pk_v = self.pk_v   # TODO don't know how to calculate it
        
        e, apk, sigma_2, cert_pk_o = self.owner.tokenReq(sigma_v, self.delta_t, cert_pk_v)
        
        msg = f"{self.N_v}{apk}"
        
        if self.Verify(cert_pk_o, msg, sigma_2):
            
            T = self.Dec(e)
            h_g = T["h_g"]
            c_l = T["c_l"]
            v_l = T["v_l"]
            t_exp = T["t_exp"]
            sigma_1 = T["sigma_1"]
            
            msg1 = f"{h_g}{c_l}{v_l}{t_exp}"
            
            if self.Verify(cert_pk_o, msg1, sigma_1):
                self.T_apk = dict(T=T, apk=apk)         # store(T, apk)
        
    
    def create_signature(self, no_challenge):
        signature = hashlib.sha256(f"{no_challenge}{self.delta_t}".encode()).hexdigest()
        sigma_v = pow(int(signature, 16), self.pk_v, PRIME)
        
        return sigma_v
            
    
    def Dec(self, e):
        decrypted_token_int = pow(e, self.sk_v, PRIME)
        
        token_json = self.int_to_str(decrypted_token_int)
        
        T = json.loads(token_json)
        
        return T
    
    
    def Verify(self, pk_o, msg, sigma):
        if (pow(msg, pk_o, PRIME) == sigma):
            return True
        
        else:
            return False
        
    
    def Attestation(self, root):
        # V uses aggregator[0] as the root for the aggregation process
        A_1 = root
        
        N = random.randint(1, 10)
        T = self.T_apk["T"]
        
        Ch = {"N": N, "T": T}
        
        alpha_1 = A_1.send_att_req(Ch)  # alpha_1 will be the aggregation of alla alphas returned
        
        h = self.owner.getGoodConfigs()
        h_g = hashlib.sha256("".join(h).encode()).hexdigest()
        
        c_l = T["c_l"]
        v_l = T["v_l"]
        
        M = f"{h_g}{N}{c_l}{v_l}"
        
        apk = self.T_apk["apk"]
        
        # Verify returns a list Beta, if the list is empty then is trustworthy 
        self.Beta = self.Verify(apk, alpha_1, M)
        
        if self.Beta == None:
            print("Network trustworthy. End of protocol.")
        else:
            print("Network not trustworthy. Learning identity and configuration of all bad devices. End of protocol.")
            
            
    def int_to_str(i):
        length = (i.bit_length() + 7) // 8
        
        return i.to_bytes(length, 'big').decode('utf-8')
    
    def Verify(self, apk, alpha_1, M):
        Beta = None
        
        # resta da fare solo questo check
            
        return Beta
        
        
        
        
        
        