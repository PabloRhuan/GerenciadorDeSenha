
# Gerenciador de Senhas Seguro

Este é um gerenciador de senhas simples e seguro desenvolvido em Java. O projeto permite que usuários armazenem, gerenciem e validem senhas de forma segura, utilizando autenticação em dois fatores (TOTP) e verificação contra senhas vazadas utilizando a API do "Have I Been Pwned".

## 🚀 Funcionalidades

- ✔️ Armazenamento seguro de credenciais
- ✔️ Verificação de senhas vazadas (API Have I Been Pwned)
- ✔️ Autenticação em dois fatores (TOTP)
- ✔️ Interface em linha de comando simples e funcional
- ✔️ Criptografia de senhas

## 🔧 Tecnologias utilizadas

- Java 17+
- API Have I Been Pwned (https://haveibeenpwned.com/API/v3)
- Algoritmo TOTP (Time-based One-Time Password)
- Criptografia AES para armazenamento seguro

## 📦 Instalação

1. Clone o repositório:

```bash
git clone https://github.com/PabloRhuan/GerenciadorDeSenha.git
```

2. Compile o projeto:

```bash
javac -d bin src/**/*.java
```

3. Execute o programa:

```bash
java -cp bin App
```

## ✅ Como utilizar

- Na primeira execução, será gerado um segredo para autenticação em dois fatores.
- Use um aplicativo como Google Authenticator para escanear o QR Code ou inserir a chave manualmente.
- Acesse o menu do gerenciador para adicionar, listar ou excluir credenciais.

## 🔒 Segurança

- As senhas são armazenadas localmente de forma criptografada.
- O sistema verifica se a senha já apareceu em vazamentos públicos usando a API HIBP (com implementação de k-anonimato).
- Utiliza autenticação em dois fatores (2FA) baseada em TOTP.

## 🤝 Contribuição

Contribuições são bem-vindas! Sinta-se livre para abrir issues ou enviar pull requests.

## 📝 Licença

Este projeto está sob a licença MIT.
