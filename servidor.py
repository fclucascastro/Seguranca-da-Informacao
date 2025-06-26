# servidor.py
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
# Privada do servidor (para assinar)
sk = SigningKey.from_pem(open("server_private.pem", "rb").read())
# Pública do cliente (para verificar)
vk_cliente = VerifyingKey.from_pem(open("client.keys", "rb").read())

# 3) Gera DH do servidor
b = random.randint(1, 100)
B = pow(g, b, p)
print(f"[Servidor] Chave pública B: {B}")

# 4) Inicia o socket
server = socket.socket()
server.bind(('localhost', 5000))
server.listen(1)
print("[Servidor] Aguardando cliente...")
conn, addr = server.accept()
print(f"[Servidor] Conectado por {addr}")

# 5) Recebe A assinado
data = conn.recv(4096)
msg = json.loads(data.decode())
A = msg["A"]
sig_A = bytes.fromhex(msg["signature"])
user_cliente = msg["username"]
print(f"[Servidor] Recebido A={A} de {user_cliente}")

# 6) Verifica assinatura de A
texto = f"{A} {user_cliente}".encode()
if not vk_cliente.verify(sig_A, texto, hashfunc=hashlib.sha256):
    print("[Servidor] Assinatura de A inválida! Encerrando.")
    conn.close()
    server.close()
    exit(1)
print("[Servidor] Assinatura de A verificada com sucesso.")

# 7) Calcula e mostra chave secreta
S = pow(A, b, p)
print(f"[Servidor] Chave secreta S: {S}")

# 8) Derivação de chaves (PBKDF2)
salt, key_aes, key_hmac = derive_keys(S)
print(f"Salt gerado    (hex): {salt.hex()}")
print(f"Key_AES  (hex): {key_aes.hex()}")
print(f"Key_HMAC (hex): {key_hmac.hex()}")

# 9) Assina B e envia de volta (inclui salt)
user_servidor = "ServidorSeguranca2025"
texto2 = f"{B} {user_servidor}".encode()
sig_B = sk.sign_deterministic(texto2, hashfunc=hashlib.sha256)
response = {
    "B": B,
    "signature": sig_B.hex(),
    "username": user_servidor,
    "salt": salt.hex()
}
conn.send(json.dumps(response).encode())
print("[Servidor] Enviou B assinado e salt ao cliente.")

# 10) Fecha conexão
conn.close()
server.close()
