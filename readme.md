# MedVault-Sec: Cofre e Transferência Segura de Laudos Médicos (PUCPR)

Projeto Final da disciplina **PSE102A - Segurança da Informação** (Bacharelado em Engenharia de Software - PUCPR).
**Professor:** Prof. MSc. Luis Gonzaga de Paulo (`luis.gonzaga@pucpr.br`)

## Integrantes da Equipe
- **João Vicente Kochinski** (Matrícula: [INSERIR_MATRICULA])
- **Pedro Matta** (Matrícula: [INSERIR_MATRICULA])
- **Dominic Skiba** (Matrícula: [INSERIR_MATRICULA])
- **Leonardo Barbosa** (Matrícula: [INSERIR_MATRICULA])

## Arquitetura e Alinhamento com os Resultados de Aprendizagem (RAs)
- **RA1 (Autenticação e Controle de Acesso):** Autenticação Multifator (Senha com derivação `PBKDF2-HMAC-SHA256` de 100.000 iterações + `TOTP` RFC 6238 via `pyotp`) e Controle de Acesso Baseado em Papéis (`RBAC` estrito entre os papéis `MEDICO` e `RECEPCAO`, aplicando o Princípio do Menor Privilégio).
- **RA2 (Sistemas Criptográficos):** Proteção de dados em trânsito via **TLS 1.3** com certificados digitais X.509 RSA-2048 (`OpenSSL`) e proteção de dados em repouso com cifragem autenticada **AES-256-GCM** combinada com assinatura de integridade **HMAC-SHA256**.
- **RA3 (Detecção e Prevenção de Intrusão e Hardening):** Monitoramento contínuo de eventos de segurança em `/var/log/medvault/security.log` e módulo **IPS ativo** que detecta ataques de força bruta ou payloads malformados e bloqueia imediatamente o IP atacante no firewall do kernel via `iptables -I INPUT 1 -s <IP> -j DROP`.

## Topologia de Rede (Docker Compose)
- Sub-rede Bridge Isolada: `172.28.0.0/24` (`rede_medvault`)
- **Nó 1 (`medvault-server`):** `172.28.0.10:8443` (Servidor TLS Python + Cofre AES-256-GCM + Motor IPS/iptables)
- **Nó 2 (`medvault-client`):** `172.28.0.20` (Estação Cliente CLI + Simulador de Casos de Teste)

## Como Executar o Ambiente (Reprodutibilidade)

### 1. Subir os contêineres
```bash
docker compose up -d --build