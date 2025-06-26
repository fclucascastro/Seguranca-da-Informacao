# servidor.py
import socket
import random
import hashlib
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1

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

# 7) Assina B e envia de volta
user_servidor = "ServidorSeguranca2025"
texto2 = f"{B} {user_servidor}".encode()
sig_B = sk.sign_deterministic(texto2, hashfunc=hashlib.sha256)
response = {
    "B": B,
    "signature": sig_B.hex(),
    "username": user_servidor
}
conn.send(json.dumps(response).encode())
print("[Servidor] Enviou B assinado ao cliente.")

# 8) Calcula e mostra chave secreta
S = pow(A, b, p)
print(f"[Servidor] Chave secreta S: {S}")

conn.close()
server.close()
