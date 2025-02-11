import random
from sympy import isprime
import math
import hashlib
import time
import json

########## OWNER ##########

PRIME = 23

class OWNER:
  def __init__(self, provers):
    # sk_o
    sk_o = random.randint(1, PRIME - 1)
    
    # Generation of key pairs (sk_i, pk_i) for each prover
    sk = [] # sk are just integers of group mod p
    
    for p in provers:
      sk.append(random.randint(1, PRIME - 1))
      
    print(sk)
    
    generators = self.all_generators(PRIME)
    
    self.g1 = random.choice(generators)
    self.g2 = random.choice(generators)
    self.g3 = random.choice(generators)
    
    print(self.g1, self.g2, self.g3)
    
    self.pk = []
    
    for i in range(len(provers)):
      self.pk.append(pow(self.g2, sk[i], PRIME))
      
    print(self.pk)
    
    key_pairs = []
    
    for i in range(len(provers)):
      key_pairs.append((sk[i], self.pk[i]))
    
    certificates = []
    
    for k in self.pk:
      certificates.append(self.generate_cert(k))
      
    for p, k, c in zip(provers, key_pairs, certificates):
      p.receive_trust_env(k, c)
      
    self.counters = {i: random.randint(0, 10) for i in range(1, 11)}

    
  def generate_cert(self, pk):
    cert = f"PK={pk})"
    
    return cert
  
  def all_generators(self, p):
    if not isprime(p):
        raise ValueError("p must be a prime number.")
    
    required_set = {num for num in range(1, p) if math.gcd(num, p) == 1}
    generators = []
    
    for g in range(1, p):
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
    expected_hash = hashlib.sha256(f"{self.no_callenge}{delta_t}".encode()).hexdigest()
    verified = pow(sigma_v, cert_pk_v, PRIME) == int(expected_hash, 16)
    
    if verified and check:
      token = self.generate_token()
      
    else:
      token = None
      
    e = self.Enc(token, cert_pk_v)
    
    # apk (aggregate public key) is the product of all the pk_i
    self.apk = 1
    for k in self.pk:
      self.apk = (k * self.apk) % PRIME
    
    msg = f"{self.N_v}{self.apk}"
    
    sigma_2 = self.Sign(msg)
        
    return e, self.apk, sigma_2, self.generate_cert(self.pk_o)
  
  def Enc(self, token, pk_v):
    token_json = json.dumps(token)
    
    return pow(token_json, pk_v, PRIME)  # TODO don't know if its right to do like this
  
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
    
    # Hash the message
    message_hash = int(hashlib.sha256(message).hexdigest(), 16)
    
    # Sign the hash using the owner's private key (modular arithmetic as an example)
    sigma_1 = self.Sign(message_hash)
    
    token = dict(H=H, c_l=c_l, v_l=v_l, t_exp=t_exp, sigma_1=sigma_1)
    
    return token
  
  def Sign(self, msg):
    return pow(msg, self.sk_o, PRIME)
    
  def getGoodConfigs(self):
    configs = ["conf1", "conf2", "conf3"]
    
    return configs
  
  