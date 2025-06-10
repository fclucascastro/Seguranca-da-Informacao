# 🔐 Segurança da Informação — Trabalho Prático

Este repositório contém o desenvolvimento passo a passo de uma aplicação de **mensagens seguras em Python**, usando conceitos fundamentais de **Segurança da Informação**, como:

- Troca de chaves com **Diffie-Hellman**
- Derivação de chaves com **PBKDF2**
- Criptografia simétrica com **AES (modo CBC)**
- Garantia de integridade e autenticidade com **HMAC**
- Comunicação via **sockets**

> Desenvolvido por Lucas para a disciplina de Segurança da Informação (Redes de Computadores), com foco no aprendizado gradual e explicações detalhadas.

---

## 📁 Estrutura do Projeto

```
seguranca-da-informacao/
├── cliente.py      # Código do cliente (envia mensagem segura)
├── servidor.py     # Código do servidor (recebe e valida mensagem)
├── README.md       # Este arquivo
```

---

## ⚙️ Como Executar

1. Clone o repositório:
```bash
git clone https://github.com/fclucascastro/Seguranca-da-Informacao.git
cd Seguranca-da-Informacao
```

2. Execute os scripts:
- Em um terminal:
```bash
python3 servidor.py
```
- Em outro terminal:
```bash
python3 cliente.py
```

3. Ambos os lados devem exibir a **mesma chave secreta**, confirmando o sucesso do handshake.

---

## 📚 Etapas do Projeto

- ✅ Etapa 1: Configuração inicial (ambiente, estrutura, testes)
- ✅ Etapa 2: Handshake com Diffie-Hellman (chave secreta compartilhada)
- ⏳ Etapa 3: Derivação de chaves com PBKDF2
- ⏳ Etapa 4: Criptografia AES + HMAC
- ⏳ Etapa 5: Testes finais e entrega

---

## 🎓 Objetivo Acadêmico

Este projeto foi construído com foco didático, para consolidar os conhecimentos da disciplina de **Segurança da Informação**. Cada etapa possui comentários, explicações e organização para facilitar a apresentação e revisão do conteúdo.

---

## 👨‍💻 Autor

Lucas – Curso Redes de Computadores  
[GitHub: fclucascastro](https://github.com/fclucascastro)
