# servidor.py
import socket
import random
import hashlib
import json
import requests
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from crypto_utils import derive_keys, verify_and_decrypt

# 1) Parâmetros públicos DH
p, g = 23, 5

# 2) Baixa a chave pública do cliente direto do GitHub
github_user = "fclucascastro"
url_cliente = f"https://raw.githubusercontent.com/{github_user}/Seguranca-da-Informacao/main/client.keys"
resp = requests.get(url_cliente)
resp.raise_for_status()
vk_cliente = VerifyingKey.from_pem(resp.content)

# 3) Carrega chave privada do servidor (para assinar)
sk_servidor = SigningKey.from_pem(open("server_private.pem", "rb").read())

# 4) Gera DH do servidor
b = random.randint(1, 100)
B = pow(g, b, p)
print(f"[Servidor] Chave pública B: {B}")

# 5) Inicia o socket
server = socket.socket()
server.bind(('localhost', 5000))
server.listen(1)
print("[Servidor] Aguardando cliente...")
conn, addr = server.accept()
print(f"[Servidor] Conectado por {addr}")

# 6) Recebe A assinado
data = conn.recv(4096)
msg = json.loads(data.decode())
A = msg["A"]
sig_A = bytes.fromhex(msg["signature"])
user_cliente = msg["username"]
print(f"[Servidor] Recebido A={A} de {user_cliente}")

# 7) Verifica assinatura de A
texto = f"{A} {user_cliente}".encode()
if not vk_cliente.verify(sig_A, texto, hashfunc=hashlib.sha256):
    print("[Servidor] Assinatura de A inválida! Encerrando.")
    conn.close()
    server.close()
    exit(1)
print("[Servidor] Assinatura de A verificada com sucesso.")

# 8) Calcula chave secreta e deriva chaves
S = pow(A, b, p)
print(f"[Servidor] Chave secreta S: {S}")
salt, key_aes, key_hmac = derive_keys(S)
print(f"Salt gerado    (hex): {salt.hex()}")
print(f"Key_AES  (hex): {key_aes.hex()}")
print(f"Key_HMAC (hex): {key_hmac.hex()}")

# 9) Assina B e envia de volta (inclui salt)
user_servidor = "ServidorSeguranca2025"
texto2 = f"{B} {user_servidor}".encode()
sig_B = sk_servidor.sign_deterministic(texto2, hashfunc=hashlib.sha256)
response = {
    "B": B,
    "signature": sig_B.hex(),
    "username": user_servidor,
    "salt": salt.hex()
}
conn.send(json.dumps(response).encode())
print("[Servidor] Enviou B assinado e salt ao cliente.")
print("[Servidor] Aguardando mensagem segura...")

# 10) Recebe mensagem segura (AES-CBC + HMAC)
data2 = conn.recv(8192)
msg2 = json.loads(data2.decode())
iv_hex   = msg2["iv"]
ct_hex   = msg2["ciphertext"]
tag_hex  = msg2["hmac"]
try:
    plaintext = verify_and_decrypt(key_aes, key_hmac, iv_hex, ct_hex, tag_hex)
    print(f"[Servidor] Mensagem recebida (criptografada): {plaintext}")
except ValueError:
    print("[Servidor] Falha na verificação HMAC! Mensagem rejeitada.")

# 11) Fecha conexão
conn.close()
server.close()
