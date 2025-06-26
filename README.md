# 🔐 Segurança da Informação — Trabalho Prático

Este repositório contém a implementação passo a passo de um sistema de mensagens seguras em Python, cobrindo:

* 💬 Troca de chaves com **Diffie-Hellman**.
* 🔏 Autenticação de chaves com **assinaturas ECDSA**.
* 🔑 Derivação de chaves com **PBKDF2** (Key\_AES e Key\_HMAC).
* 🔒 Criptografia **AES-CBC** e integridade com **HMAC-SHA256**.
* 📡 Comunicação via **sockets TCP**.

> Desenvolvido por Lucas Castro para a disciplina de Segurança da Informação.

---

## 📋 Estrutura do Repositório

```
seguranca-da-informacao/
├── cliente.py              # Cliente: handshake + envio seguro
├── servidor.py             # Servidor: handshake + recebimento seguro
├── crypto_utils.py         # Derivação PBKDF2 e funções AES/HMAC
├── generate_client_keys.py # Geração de chaves ECDSA do cliente
├── generate_server_keys.py # Geração de chaves ECDSA do servidor
├── client.keys             # Chave pública ECDSA do cliente
├── server.keys             # Chave pública ECDSA do servidor
├── client_private.pem      # Chave privada ECDSA do cliente (NÃO commitar)
├── server_private.pem      # Chave privada ECDSA do servidor (NÃO commitar)
├── requirements.txt        # Dependências Python do projeto
├── .gitignore              # Ignora venv e chaves privadas
└── README.md               # Este arquivo
```

---

## 🚀 Como Executar (Passo a Passo)

### 1. Pré-requisitos

* Python 3.8+ instalado.
* Git instalado.

### 2. Clonar o repositório

```bash
git clone https://github.com/fclucascastro/Seguranca-da-Informacao.git
cd Seguranca-da-Informacao
```

### 3. Preparar ambiente virtual

```bash
python3 -m venv venv
source venv/bin/activate      # (venv) no prompt
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Gerar chaves ECDSA (uma única vez)

```bash
# No venv ativo:
python generate_server_keys.py  # gera server_private.pem + server_public.pem
python generate_client_keys.py  # gera client_private.pem + client_public.pem

# Renomear e commitar apenas as chaves públicas:
mv server_public.pem server.keys
mv client_public.pem client.keys
# Chaves privadas ficam protegidas e ignoradas pelo .gitignore
```

### 5. Executar o Servidor

```bash
# No Terminal 1 (venv ativado)
python servidor.py
```

O servidor exibirá:

* Handshake Diffie-Hellman
* Verificação de assinaturas ECDSA
* Derivação de chaves PBKDF2
* Aguarda mensagem segura cifrada

### 6. Executar o Cliente

```bash
# No Terminal 2 (venv ativado)
python cliente.py
```

O cliente fará:

* Handshake completo (DH + ECDSA)
* Derivação de chaves PBKDF2
* Envio de mensagem cifrada com AES-CBC + HMAC

### 7. Verificar saída do servidor

```
[Servidor] Mensagem recebida (criptografada): Olá, servidor! Esta é uma mensagem segura.
```

Se aparecer, significa que:

* ✅ Confidencialidade (AES) foi garantida.
* ✅ Integridade (HMAC) foi verificada.
* ✅ Autenticidade (ECDSA) foi confirmada.

---

## 📚 Etapas de Desenvolvimento

1. **Configuração Inicial**: Python, VSCode e estrutura do projeto.
2. **DH Handshake**: troca de chaves Diffie-Hellman.
3. **ECDSA**: assinatura/verificação das chaves públicas.
4. **PBKDF2**: derivação de Key\_AES e Key\_HMAC.
5. **AES-CBC + HMAC**: troca de mensagem confidencial e íntegra.
6. **Testes e Documentação**: validação, comentários e apresentação.

---

## ⚙️ Dependências

```bash
pip install -r requirements.txt
```

Conteúdo de `requirements.txt`:

```
ecdsa
pycryptodome
```

---

## 👨‍💻 Autor

Lucas Castro — Projeto acadêmico de Segurança da Informação
GitHub: [fclucascastro](https://github.com/fclucascastro)
