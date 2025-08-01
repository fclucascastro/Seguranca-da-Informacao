import os
import hashlib

def derive_keys(shared_secret: int, salt: bytes = None, iterations: int = 100000):
    """
    Recebe:
      - shared_secret: inteiro (S do DH)
      - salt: bytes aleatório (se None, gera 16 bytes novos)
      - iterations: número de iterações do PBKDF2
    
    Retorna:
      - salt usado (bytes)
      - key_aes (32 bytes)
      - key_hmac (32 bytes)
    """
    # 1) Converte S para bytes
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    # 2) Gera salt se não fornecido
    if salt is None:
        salt = os.urandom(16)
    
    # 3) Deriva 64 bytes no total
    full_key = hashlib.pbkdf2_hmac(
        'sha256',
        secret_bytes,
        salt,
        iterations,
        dklen=64
    )
    # 4) Divide em duas metades
    key_aes  = full_key[:32]
    key_hmac = full_key[32:]
    
    return salt, key_aes, key_hmac




from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac

def encrypt_and_hmac(key_aes: bytes, key_hmac: bytes, plaintext: str):
    iv = AES.block_size.to_bytes(1, 'big') * 0  # tamanho do IV
    iv = __import__('os').urandom(AES.block_size)  # 16 bytes aleatórios
    cipher = AES.new(key_aes, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    tag = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).hexdigest()
    return iv.hex(), ciphertext.hex(), tag

def verify_and_decrypt(key_aes: bytes, key_hmac: bytes, iv_hex: str, ciphertext_hex: str, tag_hex: str):
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    expected = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, tag_hex):
        raise ValueError("HMAC inválido")
    plain = unpad(AES.new(key_aes, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)
    return plain.decode()
