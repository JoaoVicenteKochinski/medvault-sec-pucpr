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
```

### 2. Executar os Casos de Teste (T01, T02 e T03)
**Caso de Teste T02 (Fluxo Legítimo: Upload e Leitura com TLS + AES-256-GCM + HMAC-SHA256):**
```bash
docker exec -it medvault-client python client.py --teste t02
```

**Caso de Teste T01 (Bloqueio de Controle de Acesso RBAC com Usuário de Recepção):**
```bash
docker exec -it medvault-client python client.py --teste t01
```

**Caso de Teste T03 (Simulação de Ataque de Força Bruta e Bloqueio Automático via IPS/iptables):**
```bash
docker exec -it medvault-client python client.py --teste t03
```

### 3. Inspecionar Evidências no Servidor
**Ver laudo cifrado em repouso (AES-256-GCM):**
```bash
docker exec -it medvault-server cat /app/vault_storage/LAUDO_CARDIO_2026_001.json
```

**Ver logs de auditoria e alertas do IPS:**
```bash
docker exec -it medvault-server cat /var/log/medvault/security.log
```

**Ver regras ativas de bloqueio no Firewall (iptables):**
```bash
docker exec -it medvault-server iptables -L INPUT -n -v
```