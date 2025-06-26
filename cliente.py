# cliente.py
import socket
import random
import hashlib
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from crypto_utils import derive_keys

# 1) Parâmetros públicos DH
p = 23
g = 5

# 2) Carrega chaves ECDSA
# Privada do cliente (para assinar)
sk = SigningKey.from_pem(open("client_private.pem", "rb").read())
# Pública do servidor (para verificar)
vk_servidor = VerifyingKey.from_pem(open("server.keys", "rb").read())

# 3) Gera DH do cliente
a = random.randint(1, 100)
A = pow(g, a, p)
print(f"[Cliente] Chave pública A: {A}")

# 4) Assina A + username e envia
user_cliente = "ClientSeguranca2025"
texto = f"{A} {user_cliente}".encode()
sig_A = sk.sign_deterministic(texto, hashfunc=hashlib.sha256)
payload = {
    "A": A,
    "signature": sig_A.hex(),
    "username": user_cliente
}

client = socket.socket()
client.connect(('localhost', 5000))
client.send(json.dumps(payload).encode())
print("[Cliente] Enviou A assinado ao servidor.")

# 5) Recebe B assinado do servidor (mais salt)
data = client.recv(4096)
resp = json.loads(data.decode())
B = resp["B"]
sig_B = bytes.fromhex(resp["signature"])
user_servidor = resp["username"]
# Extrai salt enviado pelo servidor
salt = bytes.fromhex(resp["salt"])
print(f"[Cliente] Recebido B={B} de {user_servidor}")
print(f"[Cliente] Salt recebido (hex): {salt.hex()}")

# 6) Verifica assinatura de B
texto2 = f"{B} {user_servidor}".encode()
if not vk_servidor.verify(sig_B, texto2, hashfunc=hashlib.sha256):
    print("[Cliente] Assinatura de B inválida! Encerrando.")
    client.close()
    exit(1)
print("[Cliente] Assinatura de B verificada com sucesso.")

# 7) Calcula e mostra chave secreta
S = pow(B, a, p)
print(f"[Cliente] Chave secreta S: {S}")

# 8) Derivação de chaves com salt recebido
salt, key_aes, key_hmac = derive_keys(S, salt=salt)
print(f"Salt usado      (hex): {salt.hex()}")
print(f"Key_AES cliente : {key_aes.hex()}")
print(f"Key_HMAC cliente: {key_hmac.hex()}")

# 9) Fecha conexão
client.close()
