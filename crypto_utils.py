import random
import hashlib
from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_large_prime(bits=256):
    """Generate a large prime number of the given bit-length."""
    return getPrime(bits)

def generate_keys(p, g):
    """Generate an ElGamal key pair.
       Returns: (private_key, public_key) where public_key = y = g^x mod p.
    """
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return x, y

def mod_inverse(a, m):
    """Return the modular inverse of a modulo m."""
    return inverse(a, m)

def elgamal_encrypt(p, g, y, m):
    """Encrypt an integer message m using the ElGamal scheme.
       Returns a tuple (c1, c2).
    """
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(p, x, ciphertext):
    """Decrypt a ciphertext (c1, c2) using the private key x."""
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    m = (c2 * s_inv) % p
    return m

def elgamal_sign(p, g, x, message):
    """Generate an ElGamal digital signature for the given message.
       The signature is a tuple (r, s).
    """
    H = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
    # Choose k with gcd(k, p-1)=1.
    while True:
        k = random.randint(2, p - 2)
        if GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = ((H - x * r) * k_inv) % (p - 1)
    return (r, s)

def elgamal_verify(p, g, y, message, signature):
    """Verify an ElGamal signature. Returns True if valid."""
    r, s = signature
    if not (1 < r < p):
        return False
    H = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
    left = pow(g, H, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

def hash_function(*args):
    """Compute SHA256 hash over the concatenation of the given arguments.
       Returns a hexadecimal string.
    """
    data = ''.join(str(arg) for arg in args)
    return hashlib.sha256(data.encode()).hexdigest()

def aes_encrypt(key, plaintext):
    """Encrypt plaintext (bytes) using AES-256 in CBC mode.
       A random IV is generated and prepended to the ciphertext.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(key, ciphertext):
    """Decrypt ciphertext (bytes) using AES-256 in CBC mode.
       Assumes the first block is the IV.
    """
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)
