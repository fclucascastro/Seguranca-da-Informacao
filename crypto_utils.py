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
