
import socket
import random

# Parâmetros públicos do DH
p = 23
g = 5

# Gerar chave privada do cliente (a)
a = random.randint(1, 100)
A = pow(g, a, p)  # chave pública A = g^a mod p

print(f"[Cliente] Chave privada: {a}")
print(f"[Cliente] Chave pública: {A}")

# Conecta ao servidor
client = socket.socket()
client.connect(('localhost', 5000))

# Recebe B e envia A
B = int(client.recv(1024).decode())
client.send(str(A).encode())
print(f"[Cliente] Chave pública recebida (B): {B}")

# Calcula chave secreta compartilhada: S = B^a mod p
S = pow(B, a, p)
print(f"[Cliente] Chave secreta compartilhada: {S}")

client.close()
