# generate_server_keys.py
from ecdsa import SigningKey, SECP256k1

# 1) Gera a chave privada do servidor (SigningKey)
sk = SigningKey.generate(curve=SECP256k1)

# 2) Extrai a chave pública (VerifyingKey)
vk = sk.get_verifying_key()

# 3) Salva a chave privada em PEM (NÃO será commitada)
with open("server_private.pem", "wb") as f:
    f.write(sk.to_pem())

# 4) Salva a chave pública em PEM (vamos renomear para .keys e commitar)
with open("server_public.pem", "wb") as f:
    f.write(vk.to_pem())

print("✅ Chaves ECDSA do servidor geradas!")
