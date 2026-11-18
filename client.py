#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PUCPR - Bacharelado em Engenharia de Software
Disciplina: PSE102A - Seguranca da Informacao (Prof. MSc. Luis Gonzaga de Paulo)
Projeto Final: MedVault-Sec (Cliente CLI e Suite Automatizada de Casos de Teste T01 a T03)
Autores: Joao Vicente Kochinski, Pedro Matta, Dominic Skiba, Leonardo Barbosa
"""

import sys
import ssl
import json
import time
import hmac
import socket
import hashlib
import argparse
import pyotp

SERVER_HOST = "172.28.0.10"
SERVER_PORT = 8443
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
HMAC_SECRET = b"MedVault-HMAC-Integrity-Key-2026-PUCPR"

def send_request(username, password, totp_code, action, payload=None, extra=None):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    req = {
        "username": username,
        "password": password,
        "totp_code": totp_code,
        "action": action,
        "payload": payload or {}
    }
    if extra:
        req.update(extra)

    with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=8.0) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            cipher_info = ssock.cipher()
            tls_version = ssock.version()
            ssock.sendall(json.dumps(req).encode("utf-8"))
            resp_raw = ssock.recv(8192)
            resp = json.loads(resp_raw.decode("utf-8"))
            return resp, tls_version, cipher_info

def run_test_t01_rbac():
    print("=" * 75)
    print("[CASO DE TESTE T01] Verificacao de Autenticacao MFA e Controle de Acesso (RBAC - RA1)")
    print("=" * 75)
    totp_now = pyotp.TOTP(TOTP_SECRET).now()
    print(f"[*] Token MFA/TOTP gerado em tempo real para a sessao: {totp_now}")
    print("[*] Autenticando como 'atendente_pedro' (Papel: RECEPCAO) e tentando operacao restrita 'LER_LAUDO'...")
    resp, tls_ver, cipher = send_request(
        username="atendente_pedro",
        password="Recepcao@2026!",
        totp_code=totp_now,
        action="LER_LAUDO",
        payload={"laudo_id": "LAUDO_CARDIO_2026_001"}
    )
    print(f"[+] Canal Seguro: {tls_ver} | Suite: {cipher[0]}")
    print("[+] Resposta do Servidor:\n" + json.dumps(resp, indent=4, ensure_ascii=False))
    print("=" * 75)

def run_test_t02_crypto():
    print("=" * 75)
    print("[CASO DE TESTE T02] Confidencialidade e Integridade em Transito e Repouso (TLS + AES-GCM + HMAC - RA2)")
    print("=" * 75)
    totp_now = pyotp.TOTP(TOTP_SECRET).now()
    laudo_id = "LAUDO_CARDIO_2026_001"
    conteudo = "PACIENTE: Carlos Eduardo Silva (Dados Ficticios LGPD) | DIAGNOSTICO: Ritmo sinusal regular, sem isquemia aguda. Assinado: Dr. Joao Vicente (CRM-PR 99999)."
    client_hmac = hmac.new(HMAC_SECRET, conteudo.encode("utf-8"), hashlib.sha256).hexdigest()

    print(f"[*] 1. Enviando laudo '{laudo_id}' autenticado como 'dr_joao' (Papel: MEDICO)...")
    print(f"[*] HMAC-SHA256 calculado na origem: {client_hmac}")
    resp_up, tls_ver, cipher = send_request(
        username="dr_joao",
        password="Medico@2026!",
        totp_code=totp_now,
        action="UPLOAD_LAUDO",
        payload={
            "laudo_id": laudo_id,
            "conteudo": conteudo,
            "client_hmac": client_hmac
        }
    )
    print(f"[+] Canal Negociado: {tls_ver} | Cifra: {cipher[0]} ({cipher[2]} bits)")
    print("[+] Resposta de Armazenamento Cifrado (AES-256-GCM):\n" + json.dumps(resp_up, indent=4, ensure_ascii=False))

    print("\n[*] 2. Solicitando leitura e decifragem do laudo armazenado no cofre...")
    resp_read, _, _ = send_request(
        username="dr_joao",
        password="Medico@2026!",
        totp_code=totp_now,
        action="LER_LAUDO",
        payload={"laudo_id": laudo_id}
    )
    print("[+] Resposta de Leitura e Verificacao de Integridade:\n" + json.dumps(resp_read, indent=4, ensure_ascii=False))
    print("=" * 75)

def run_test_t03_ips():
    print("=" * 75)
    print("[CASO DE TESTE T03] Deteccao e Prevencao de Intrusao / Forca Bruta com Bloqueio Firewall (RA3)")
    print("=" * 75)
    for i in range(1, 5):
        print(f"\n[*] Disparando tentativa de ataque de forca bruta #{i} contra usuario 'dr_joao'...")
        try:
            resp, _, _ = send_request(
                username="dr_joao",
                password=f"SenhaInvasorErrada_{i}",
                totp_code="000000",
                action="LER_LAUDO",
                payload={"laudo_id": "LAUDO_CARDIO_2026_001"}
            )
            print(f"    -> Resposta da tentativa #{i}: {resp}")
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as e:
            print(f"    -> [BLOQUEIO IPS/IPTABLES CONFIRMADO NA TENTATIVA #{i}] Conexao descartada pelo Firewall do Servidor: {e}")
        time.sleep(0.5)
    print("=" * 75)

def main():
    parser = argparse.ArgumentParser(description="Cliente MedVault-Sec - PUCPR")
    parser.add_argument("--teste", choices=["t01", "t02", "t03", "todos"], help="Executa os casos de teste oficiais do relatorio")
    args = parser.parse_args()

    if args.teste == "t01":
        run_test_t01_rbac()
    elif args.teste == "t02":
        run_test_t02_crypto()
    elif args.teste == "t03":
        run_test_t03_ips()
    elif args.teste == "todos":
        run_test_t02_crypto()
        print()
        run_test_t01_rbac()
        print()
        run_test_t03_ips()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()