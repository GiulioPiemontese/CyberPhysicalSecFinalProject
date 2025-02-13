import random
import base64
from sympy import isprime
import math
import hashlib
import json
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5

########## OWNER ##########

PRIME = 7 #23

class OWNER:
  def __init__(self, provers):
    generators = self.all_generators(PRIME)
    
    self.g1 = random.choice(generators)
    self.g2 = random.choice(generators)
    self.g3 = random.choice(generators)
    
    print(self.g1, self.g2, self.g3)

    # Generate RSA Key Pair (in variables)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Import keys directly from variables
    self.sk_o = RSA.import_key(private_key)
    self.pk_o = RSA.import_key(public_key)
    
    # Generation of key pairs (sk_i, pk_i) for each prover
    sk = [] # sk are just integers of group mod p
    
    for p in provers:
      sk.append(random.randint(1, PRIME - 1))
      
    print(sk)
    
    
    self.pk = []
    
    for i in range(len(provers)):
      self.pk.append(pow(self.g2, sk[i], PRIME))
      
    print(self.pk)
    
    key_pairs = []
    
    for i in range(len(provers)):
      key_pairs.append((sk[i], self.pk[i]))
    
    certificates = []
    
    for k in self.pk:
      certificates.append(k)
      
    for p, k, c in zip(provers, key_pairs, certificates):
      p.receive_trust_env(k, c)
      
    self.counters = {i: random.randint(0, 10) for i in range(1, 11)}


    
  def generate_cert(self, pk):
    cert = self.pk_o.export_key()
    
    return cert
  
  
  
  def all_generators(self, p):
    if not isprime(p):
      raise ValueError("p must be a prime number.")
        
    # Set of all elements coprime with p
    required_set = {num for num in range(1, p) if math.gcd(num, p) == 1}
    generators = []
        
    for g in range(1, p):
      # Generate the set of powers of g modulo p
      generated = {pow(g, power, p) for power in range(1, p)}
      if generated == required_set:
        generators.append(g)
        
    return generators
    
    
    
  def getFreeCounter(self):
    tuple = random.choice(list(self.counters.items()))  # should be picked the free one
    cl, vl = tuple
    vl = vl + 1

    return cl, vl
  
  
  
  def get_nonce(self, nonce):
    self.N_v = nonce
    
    self.no_callenge = random.randint(1, 10)
    
    return self.no_callenge
  
  
  
  def tokenReq(self, sigma_v, delta_t, cert_pk_v):
    self.delta_t = delta_t
    
    # policy check
    check = self.checkPolicy(delta_t)
    
    # Verify the signature
    verified = self.verify_signature(sigma_v, self.no_callenge, delta_t, cert_pk_v)
    
    if verified and check:
      token = self.generate_token()
      print("Token generated by Owner.")
      
    else:
      token = None
      print("Error during token generation. Abort process.")
      return 0
    
    # Token encryption using RSA with pk_v  
    e = self.Enc(token, cert_pk_v)
    
    # apk (aggregate public key) is the product of all the pk_i
    self.apk = 1
    for k in self.pk:
      self.apk = (k * self.apk) % PRIME
    
    msg = f"{self.N_v}{self.apk}".encode()
    
    sigma_2 = self.Sign(msg)
        
    return e, self.apk, sigma_2, self.generate_cert(self.pk_o)
  
  
  
  def verify_signature(self, sigma_v, no_challenge, delta_t, cert_pk_v):
    """Verifies the signature"""
    try:
      # Construct the message from no_challenge and delta_t
      message = f"{no_challenge}{delta_t}".encode()

      # Hash the message
      hashed_msg = SHA256.new(message)

      # Import the provided public key for verification
      cert_public_key = RSA.import_key(cert_pk_v)

      # Verify the signature
      pkcs1_15.new(cert_public_key).verify(hashed_msg, sigma_v)
              
      return True  # Signature is valid
    
    except (ValueError, TypeError):
      return False  # Signature verification failed
            


  def Enc(self, token, pk_v):
    if isinstance(pk_v, RSA.RsaKey):
        pk_v = pk_v.export_key()

    public_key = RSA.import_key(pk_v)
    cipher_rsa = PKCS1_v1_5.new(public_key)

    encrypted_token = {}
    for key, value in token.items():
        if key == "sigma_1":  # Skip encryption for sigma
            encrypted_token[key] = value
            continue

        # Convert lists to JSON format for consistent decryption
        if isinstance(value, list):
            value = json.dumps(value)  # Store lists as JSON strings

        value_str = str(value).encode('utf-8')

        encrypted_value = base64.b64encode(cipher_rsa.encrypt(value_str)).decode('utf-8')
        encrypted_token[key] = encrypted_value

    return encrypted_token


  def checkPolicy(self, delta_t):
    check = delta_t <= 3600  # Token valid for less than 1 hour
    
    return check
  
  
  
  def generate_token(self):
    token = {}
    
    H = self.getGoodConfigs()
    
    h_g = hashlib.sha256("".join(H).encode()).hexdigest()
    
    c_l, v_l = self.getFreeCounter()
    
    # Compute expiration time
    t_exp = int(time.time() + self.delta_t)
    
    # Concatenate h_g, c_l, v_l, and t_exp as a single message
    message = f"{h_g}{c_l}{v_l}{t_exp}".encode()
        
    # Sign the hash using the owner's private key (modular arithmetic as an example)
    sigma_1 = self.Sign(message)
    
    token = dict(H=H, c_l=c_l, v_l=v_l, t_exp=t_exp, sigma_1=sigma_1)
    
    return token
  
  
  
  def Sign(self, msg):
    # Hash the message
    hashed_msg = SHA256.new(msg)

    # Sign the message
    signature = pkcs1_15.new(self.sk_o).sign(hashed_msg)
        
    return signature            
    

    
  def getGoodConfigs(self):
    configs = ["conf1", "conf2", "conf3"]
    
    return configs
  
  