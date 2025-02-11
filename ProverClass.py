from DeviceClass import DEVICE
import hashlib

PRIME = 23

class PROVER:
    def __init__(self, id):
        self.id = id
        self.sk = None
        self.pk = None
        self.cert = None
        self.M = "Default MSG"
        
    def receive_trust_env(self, key_pair, cert):
        self.sk = key_pair[0]
        self.pk = key_pair[1]
        self.cert = cert
    
    def get_id(self):
        return self.id
    
    # just the method called by aggregator to forward Ch that Create the alpha for response
    def send_att_req(self, Ch):
        return self.CreateResponse(Ch)
    
    # create the alpha to be sent back to the caller
    def CreateResponse(self, Ch):
        T = Ch["T"]
        
        c_l = T["c_l"]
        v_l = T["v_l"]
        
        N = Ch["N"]
        
        H = T["H"]
        
        h = self.getSoftConf()
    
        if h in H:
            h = hashlib.sha256("".join(H).encode()).hexdigest() # h <- h_g
        
        # msg1 = h|N|c_l|v_l
        msg = f"{h}{N}{c_l}{v_l}"
        
        # Sign the 2 msg: h|N|c_l|v_l and M
        msg1 = self.Sign(self.sk, msg)
        msg2 = self.Sign(self.sk, self.M)        
        
        # alpha = Sign(sk; h|N|c_l|v_l, M) TODO: but i think that they are not concatenated bu are returned as couple of msg
        alpha = f"{msg1}{msg2}"
        
        return alpha
    
    def Sign(self, sk, msg):
        return pow(msg, sk, PRIME)
    
    def getSoftConf(self):
        conf = "conf1"
        
        return conf
    
    def __str__(self):
        return f"ID={self.id}, SK={self.sk}, PK={self.pk}, CERT={self.cert}"
    
    def __repr__(self):
        return f"Prover:{self.id}"