import random
import hashlib
import base64
import json
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

PRIME = 23

class VERIFIER:
    def __init__(self, owner, aggregators):
        # Generate RSA Key Pair (in variables)
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Import keys directly from variables
        self.sk_v = RSA.import_key(private_key)
        self.pk_v = RSA.import_key(public_key)

        self.id = random.randint(1, PRIME)
        self.delta_t = 3600         # max expiration time
        self.aggregators = aggregators
        self.owner = owner
        
        
    
    def tokenReq(self):
        self.N_v = random.randint(1, 10)
        
        no_challenge = self.owner.get_nonce(self.N_v)
        
        sigma_v = self.Sign(no_challenge)
        
        cert_pk_v = self.pk_v.export_key()
        
        e, apk, sigma_2, cert_pk_o = self.owner.tokenReq(sigma_v, self.delta_t, cert_pk_v)
        
        msg = f"{self.N_v}{apk}".encode()
        
        if self.Verify_sig(cert_pk_o, msg, sigma_2):
            
            T = self.Dec(e)
            h_g = hashlib.sha256("".join(T["H"]).encode()).hexdigest()
            c_l = T["c_l"]
            v_l = T["v_l"]
            t_exp = T["t_exp"]
            sigma_1 = T["sigma_1"]
            
            msg1 = f"{h_g}{c_l}{v_l}{t_exp}".encode()
            
            if self.Verify_sig(cert_pk_o, msg1, sigma_1):
                self.T_apk = dict(T=T, apk=apk)         # store(T, apk)
        
        
    
    def Sign(self, no_challenge):
        # Message to sign
        message = f"{no_challenge}{self.delta_t}".encode()

        # Hash the message
        hashed_msg = SHA256.new(message)

        # Sign the message
        signature = pkcs1_15.new(self.sk_v).sign(hashed_msg)
        
        return signature
    
    
    
    def Dec(self, e):
        if isinstance(self.sk_v, RSA.RsaKey):
            private_key = self.sk_v
        else:
            private_key = RSA.import_key(self.sk_v)

        cipher_rsa = PKCS1_v1_5.new(private_key)

        decrypted_token = {}
        for key, encrypted_value in e.items():
            if key == "sigma_1":
                decrypted_token[key] = encrypted_value
                continue

            encrypted_value_bytes = base64.b64decode(encrypted_value)
            decrypted_value_bytes = cipher_rsa.decrypt(encrypted_value_bytes, None)
            decrypted_value = decrypted_value_bytes.decode('utf-8')

            # Convert JSON strings back to lists
            try:
                decrypted_value = json.loads(decrypted_value)  # Restore list format
            except json.JSONDecodeError:
                pass  # If it's not a JSON list, keep it as a string

            decrypted_token[key] = decrypted_value

        return decrypted_token
    
    
    
    def Verify_sig(self, cert_pk_o, msg, sigma):
        """Verifies the signature"""
        try:
            # Hash the message
            hashed_msg = SHA256.new(msg)

            # Import the provided public key for verification
            cert_public_key = RSA.import_key(cert_pk_o)

            # Verify the signature
            pkcs1_15.new(cert_public_key).verify(hashed_msg, sigma)
                
            return True  # Signature is valid
        except (ValueError, TypeError):
            return False  # Signature verification failed
        
    
    
    def Attestation(self, root):
        # V uses aggregator[0] as the root for the aggregation process
        A_1 = root
        
        N = random.randint(1, 10)
        T = self.T_apk["T"]
        
        Ch = {"N": N, "T": T}
        
        alpha_1 = A_1.send_att_req(Ch)  # alpha_1 will be the aggregation of all alphas returned
        
        h = self.owner.getGoodConfigs()
        h_g = hashlib.sha256("".join(h).encode()).hexdigest()
        
        c_l = T["c_l"]
        v_l = T["v_l"]
        
        M = f"{h_g}{N}{c_l}{v_l}".encode()      # TODO: controllare h come viene fatto
        
        apk = self.T_apk["apk"]
        
        # Verify returns a list Beta, if the list is empty then is trustworthy 
        self.Beta = self.Verify_beta(apk, alpha_1, M)
        
        if self.Beta == None:
            print("Network trustworthy. End of protocol.")
        else:
            print("Network not trustworthy. Learning identity and configuration of all bad devices. End of protocol.")
            for conf in self.Beta:
                print(conf, "\n")
            

    
    def Verify_beta(self, apk, alpha_1, M):
        Beta = [] # start from empty list
        
        # resta da fare solo questo check
            
        return Beta
        
