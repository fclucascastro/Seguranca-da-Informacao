# generate_client_keys.py
from ecdsa import SigningKey, SECP256k1

# 1) Gera a chave privada do cliente
sk = SigningKey.generate(curve=SECP256k1)
# 2) Extrai a chave pública
vk = sk.get_verifying_key()

# 3) Salva a chave privada em PEM (keep secret)
with open("client_private.pem", "wb") as f:
    f.write(sk.to_pem())

# 4) Salva a chave pública em PEM (vamos renomear para .keys)
with open("client_public.pem", "wb") as f:
    f.write(vk.to_pem())

print("✅ Chaves ECDSA do cliente geradas!")
