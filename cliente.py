# cliente.py
import socket, random, hashlib, json
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from crypto_utils import derive_keys, encrypt_and_hmac

# 1) Parâmetros públicos DH
p, g = 23, 5

# 2) Carrega chaves ECDSA
sk = SigningKey.from_pem(open("client_private.pem", "rb").read())
vk_ser = VerifyingKey.from_pem(open("server.keys", "rb").read())

# 3) Gera DH do cliente
a = random.randint(1, 100); A = pow(g, a, p)
print(f"[Cliente] Chave pública A: {A}")

# 4) Envia A assinado
user_c = "ClientSeguranca2025"
texto = f"{A} {user_c}".encode()
sig_A = sk.sign_deterministic(texto, hashfunc=hashlib.sha256)
payload = {"A": A, "signature": sig_A.hex(), "username": user_c}
client = socket.socket(); client.connect(('localhost', 5000))
client.send(json.dumps(payload).encode())
print("[Cliente] Handshake iniciado.")

# 5) Recebe B assinado + salt
data = client.recv(4096); resp = json.loads(data.decode())
B = resp["B"]; sig_B = bytes.fromhex(resp["signature"])
user_s = resp["username"]; salt = bytes.fromhex(resp["salt"])
texto2 = f"{B} {user_s}".encode()
if not vk_ser.verify(sig_B, texto2, hashfunc=hashlib.sha256):
    print("[Cliente] Assinatura B inválida"); client.close(); exit(1)
print("[Cliente] Handshake completo.")

# 6) Calcula S e deriva chaves
S = pow(B, a, p)
_, key_aes, key_hmac = derive_keys(S, salt=salt)
print(f"[Cliente] Derivação OK. Salt: {salt.hex()}")

# 7) Envia mensagem segura
mensagem = "Olá, servidor! Esta é uma mensagem segura."
iv, ct, tag = encrypt_and_hmac(key_aes, key_hmac, mensagem)
secure_payload = {"iv": iv, "ciphertext": ct, "hmac": tag}
client.send(json.dumps(secure_payload).encode())
print("[Cliente] Mensagem segura enviada.")

client.close()
