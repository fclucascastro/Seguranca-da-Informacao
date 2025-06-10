# servidor.py - Handshake Diffie-Hellman, a ideia aqui seria o servidor realizar o handshake DH com um cliente.

import socket
import random

p = 23  # número primo (público)
g = 5   # gerador (público)

# Gerar chave privada do servidor (b)
b = random.randint(1, 100)
B = pow(g, b, p)  # chave pública B = g^b mod p

print(f"[Servidor] Chave privada: {b}")
print(f"[Servidor] Chave pública: {B}")

# Cria socket e aguarda conexão
server = socket.socket()
server.bind(('localhost', 5000))
server.listen(1)
print("[Servidor] Aguardando conexão...")

conn, addr = server.accept()
print(f"[Servidor] Cliente conectado: {addr}")

# Envia B para o cliente e recebe A
conn.send(str(B).encode())
A = int(conn.recv(1024).decode())
print(f"[Servidor] Chave pública recebida (A): {A}")

# Calcula chave secreta compartilhada: S = A^b mod p
S = pow(A, b, p)
print(f"[Servidor] Chave secreta compartilhada: {S}")

conn.close()
server.close()
