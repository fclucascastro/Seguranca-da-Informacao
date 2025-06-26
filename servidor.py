# servidor.py
import socket, random, hashlib, json
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from crypto_utils import derive_keys, verify_and_decrypt

# 1) Parâmetros públicos DH
p, g = 23, 5

# 2) Carrega chaves ECDSA
sk = SigningKey.from_pem(open("server_private.pem", "rb").read())
vk_cliente = VerifyingKey.from_pem(open("client.keys", "rb").read())

# 3) Gera DH do servidor
b = random.randint(1, 100); B = pow(g, b, p)
print(f"[Servidor] Chave pública B: {B}")

# 4) Inicia socket
server = socket.socket()
server.bind(('localhost', 5000))
server.listen(1)
print("[Servidor] Aguardando cliente...")
conn, addr = server.accept()
print(f"[Servidor] Conectado por {addr}")

# 5) Handshake ECDSA (recebe A)
data = conn.recv(4096); msg = json.loads(data.decode())
A = msg["A"]; sig_A = bytes.fromhex(msg["signature"]); user_c = msg["username"]
texto = f"{A} {user_c}".encode()
if not vk_cliente.verify(sig_A, texto, hashfunc=hashlib.sha256):
    print("[Servidor] Assinatura A inválida"); conn.close(); exit(1)
print("[Servidor] Assinatura de A verificada.")

# 6) Calcula S e deriva chaves
S = pow(A, b, p)
salt, key_aes, key_hmac = derive_keys(S)
print(f"[Servidor] Salt: {salt.hex()}")

# 7) Envia B assinado + salt
user_s = "ServidorSeguranca2025"
texto2 = f"{B} {user_s}".encode()
sig_B = sk.sign_deterministic(texto2, hashfunc=hashlib.sha256)
response = {"B": B, "signature": sig_B.hex(), "username": user_s, "salt": salt.hex()}
conn.send(json.dumps(response).encode())
print("[Servidor] Handshake completo. Agora aguardando mensagem segura...")

# 8) Recebe mensagem segura (AES-CBC + HMAC)
data2 = conn.recv(8192); msg2 = json.loads(data2.decode())
iv_hex, ct_hex, tag_hex = msg2["iv"], msg2["ciphertext"], msg2["hmac"]
try:
    plaintext = verify_and_decrypt(key_aes, key_hmac, iv_hex, ct_hex, tag_hex)
    print(f"[Servidor] Mensagem recebida (criptografada): {plaintext}")
except ValueError:
    print("[Servidor] Falha na verificação HMAC! Mensagem rejeitada.")

conn.close()
server.close()
