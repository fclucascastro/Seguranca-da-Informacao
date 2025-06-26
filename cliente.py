# cliente.py
import socket
import random
import hashlib
import json
import requests
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from crypto_utils import derive_keys, encrypt_and_hmac

# 1) Parâmetros públicos DH
p, g = 23, 5

# 2) Baixa a chave pública do servidor direto do GitHub
github_user = "fclucascastro"
url_servidor = f"https://raw.githubusercontent.com/{github_user}/Seguranca-da-Informacao/main/server.keys"
resp = requests.get(url_servidor)
resp.raise_for_status()
vk_servidor = VerifyingKey.from_pem(resp.content)

# 3) Carrega chave privada do cliente (para assinar)
sk_cliente = SigningKey.from_pem(open("client_private.pem", "rb").read())

# 4) Gera DH do cliente
a = random.randint(1, 100)
A = pow(g, a, p)
print(f"[Cliente] Chave pública A: {A}")

# 5) Assina A + username e envia
user_cliente = "ClientSeguranca2025"
texto = f"{A} {user_cliente}".encode()
sig_A = sk_cliente.sign_deterministic(texto, hashfunc=hashlib.sha256)
payload = {
    "A": A,
    "signature": sig_A.hex(),
    "username": user_cliente
}

client = socket.socket()
client.connect(('localhost', 5000))
client.send(json.dumps(payload).encode())
print("[Cliente] Enviou A assinado ao servidor.")

# 6) Recebe B assinado + salt
data = client.recv(4096)
resp = json.loads(data.decode())
B = resp["B"]
sig_B = bytes.fromhex(resp["signature"])
user_ser = resp["username"]
salt = bytes.fromhex(resp["salt"])
print(f"[Cliente] Recebido B={B} de {user_ser}")
print(f"[Cliente] Salt recebido (hex): {salt.hex()}")

# 7) Verifica assinatura de B
texto2 = f"{B} {user_ser}".encode()
if not vk_servidor.verify(sig_B, texto2, hashfunc=hashlib.sha256):
    print("[Cliente] Assinatura de B inválida! Encerrando.")
    client.close()
    exit(1)
print("[Cliente] Assinatura de B verificada com sucesso.")

# 8) Calcula chave secreta e deriva chaves
S = pow(B, a, p)
print(f"[Cliente] Chave secreta S: {S}")
_, key_aes, key_hmac = derive_keys(S, salt=salt)
print(f"Salt usado      (hex): {salt.hex()}")
print(f"Key_AES cliente : {key_aes.hex()}")
print(f"Key_HMAC cliente: {key_hmac.hex()}")

# 9) Envia mensagem segura (AES-CBC + HMAC)
mensagem = "Olá, servidor! Esta é uma mensagem segura."
iv, ct, tag = encrypt_and_hmac(key_aes, key_hmac, mensagem)
secure_payload = {"iv": iv, "ciphertext": ct, "hmac": tag}
client.send(json.dumps(secure_payload).encode())
print("[Cliente] Mensagem segura enviada.")

# 10) Fecha conexão
client.close()
