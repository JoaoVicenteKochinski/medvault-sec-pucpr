#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PUCPR - Bacharelado em Engenharia de Software
Disciplina: PSE102A - Seguranca da Informacao (Prof. MSc. Luis Gonzaga de Paulo)
Projeto Final: MedVault-Sec (Servidor TLS + MFA/RBAC + AES-256-GCM/HMAC + IPS/iptables)
Autores: Joao Vicente Kochinski, Pedro Matta, Dominic Skiba, Leonardo Barbosa
"""

import os
import ssl
import json
import time
import hmac
import socket
import hashlib
import logging
import subprocess
from datetime import datetime
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuracoes de Rede e Caminhos
HOST = "0.0.0.0"
PORT = 8443
CERT_FILE = "/app/certs/server.crt"
KEY_FILE = "/app/certs/server.key"
VAULT_DIR = "/app/vault_storage"
LOG_FILE = "/var/log/medvault/security.log"

os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Configuracao de Logs de Auditoria e Seguranca (RA3)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Chaves Criptograficas do Cofre (RA2)
MASTER_KEY = hashlib.pbkdf2_hmac("sha256", b"MedVault-MasterSecret-PUCPR-2026", b"SaltFixoClinica", 100000, dklen=32)
HMAC_SECRET = b"MedVault-HMAC-Integrity-Key-2026-PUCPR"

# Segredo TOTP compartilhado para Segundo Fator (MFA - RA1)
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()

# Base de Usuarios com Controle de Acesso Baseado em Papeis (RBAC - RA1)
USERS_DB = {
    "dr_joao": {
        "salt": b"salt_medico_01",
        "password_hash": hash_password("Medico@2026!", b"salt_medico_01"),
        "role": "MEDICO",
        "permissions": ["UPLOAD_LAUDO", "LER_LAUDO", "LISTAR_LAUDOS"],
        "totp_secret": TOTP_SECRET
    },
    "atendente_pedro": {
        "salt": b"salt_recepcao_02",
        "password_hash": hash_password("Recepcao@2026!", b"salt_recepcao_02"),
        "role": "RECEPCAO",
        "permissions": ["LISTAR_LAUDOS"],
        "totp_secret": TOTP_SECRET
    }
}

# Estado do Motor IPS (Deteccao e Prevencao de Intrusao - RA3)
FAILED_ATTEMPTS = {}
BLOCKED_IPS = set()
MAX_FAILURES = 3
WINDOW_SECONDS = 60

def block_ip_iptables(ip_address: str, reason: str):
    BLOCKED_IPS.add(ip_address)
    logging.critical(f"[ALERTA IDS/IPS - INTRUSAO DETECTADA] Origem: {ip_address} | Motivo: {reason} | Acao: BLOQUEIO IPTABLES DROP")
    try:
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        res = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"], check=True)
            logging.info(f"[FIREWALL IPTABLES] Regra inserida com sucesso: iptables -I INPUT 1 -s {ip_address} -j DROP")
    except Exception as e:
        logging.warning(f"[FIREWALL IPTABLES] Bloqueio mantido em memoria (aviso de permissao kernel: {e})")

def record_failure(ip_address: str, username: str, reason: str):
    now = time.time()
    history = FAILED_ATTEMPTS.get(ip_address, [])
    history = [t for t in history if now - t < WINDOW_SECONDS]
    history.append(now)
    FAILED_ATTEMPTS[ip_address] = history
    logging.warning(f"[AUTH_FAIL] IP: {ip_address} | Usuario: {username} | Motivo: {reason} | Tentativa {len(history)}/{MAX_FAILURES}")
    if len(history) >= MAX_FAILURES:
        block_ip_iptables(ip_address, f"Excesso de falhas de autenticacao/forca bruta ({len(history)} tentativas)")

def encrypt_and_store_laudo(laudo_id: str, conteudo: str, autor: str) -> dict:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    plaintext_bytes = conteudo.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, laudo_id.encode("utf-8"))
    
    mac = hmac.new(HMAC_SECRET, nonce + ciphertext, hashlib.sha256).hexdigest()
    sha256_original = hashlib.sha256(plaintext_bytes).hexdigest()

    record = {
        "laudo_id": laudo_id,
        "autor": autor,
        "timestamp": datetime.now().isoformat(),
        "algoritmo": "AES-256-GCM + HMAC-SHA256",
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "hmac_sha256": mac,
        "sha256_plaintext": sha256_original
    }
    filepath = os.path.join(VAULT_DIR, f"{laudo_id}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=4)
    return record

def decrypt_and_verify_laudo(laudo_id: str) -> dict:
    filepath = os.path.join(VAULT_DIR, f"{laudo_id}.json")
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Laudo '{laudo_id}' nao encontrado no cofre.")
    
    with open(filepath, "r", encoding="utf-8") as f:
        record = json.load(f)
    
    nonce = bytes.fromhex(record["nonce_hex"])
    ciphertext = bytes.fromhex(record["ciphertext_hex"])
    stored_mac = record["hmac_sha256"]
    
    computed_mac = hmac.new(HMAC_SECRET, nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(stored_mac, computed_mac):
        raise ValueError("VIOLACAO DE INTEGRIDADE DETECTADA! O HMAC-SHA256 do arquivo foi adulterado.")
    
    aesgcm = AESGCM(MASTER_KEY)
    plaintext = aesgcm.decrypt(nonce, ciphertext, laudo_id.encode("utf-8")).decode("utf-8")
    return {
        "laudo_id": laudo_id,
        "autor": record["autor"],
        "timestamp": record["timestamp"],
        "integridade_hmac": "VALIDA (HMAC-SHA256 verificado)",
        "conteudo_decifrado": plaintext
    }

def handle_client(conn: ssl.SSLSocket, addr):
    client_ip = addr[0]
    if client_ip in BLOCKED_IPS:
        logging.error(f"[CONEXAO_REJEITADA_IPS] IP bloqueado tentou reconectar: {client_ip}")
        conn.close()
        return

    try:
        conn.settimeout(15.0)
        raw_data = conn.recv(8192)
        if not raw_data:
            return
        
        try:
            req = json.loads(raw_data.decode("utf-8"))
        except Exception:
            record_failure(client_ip, "DESCONHECIDO", "Payload JSON malformado/invalido")
            conn.sendall(json.dumps({"status": "ERRO", "codigo": 400, "mensagem": "Payload JSON invalido."}).encode("utf-8"))
            return

        username = str(req.get("username", "")).strip()
        password = str(req.get("password", ""))
        totp_code = str(req.get("totp_code", "")).strip()
        action = str(req.get("action", "")).strip()
        payload = req.get("payload", {})

        user = USERS_DB.get(username)
        if not user:
            record_failure(client_ip, username, "Usuario inexistente")
            conn.sendall(json.dumps({"status": "ERRO", "codigo": 401, "mensagem": "Credenciais invalidas."}).encode("utf-8"))
            return

        candidate_hash = hash_password(password, user["salt"])
        if not hmac.compare_digest(candidate_hash, user["password_hash"]):
            record_failure(client_ip, username, "Senha incorreta (PBKDF2 mismatch)")
            conn.sendall(json.dumps({"status": "ERRO", "codigo": 401, "mensagem": "Credenciais invalidas."}).encode("utf-8"))
            return

        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(totp_code, valid_window=1):
            record_failure(client_ip, username, "Codigo MFA/TOTP invalido ou expirado")
            conn.sendall(json.dumps({"status": "ERRO", "codigo": 401, "mensagem": "Falha na autenticacao Multifator (TOTP invalido)."}).encode("utf-8"))
            return

        logging.info(f"[AUTH_OK] IP: {client_ip} | Usuario: {username} | Papel (RBAC): {user['role']} | MFA: VALIDADO")

        if action not in user["permissions"]:
            logging.warning(
                f"[RBAC_ACCESS_DENIED] IP: {client_ip} | Usuario: {username} (Papel: {user['role']}) "
                f"tentou executar acao nao autorizada: '{action}'"
            )
            conn.sendall(json.dumps({
                "status": "ACESSO_NEGADO",
                "codigo": 403,
                "mensagem": f"RBAC: O papel '{user['role']}' nao possui permissao para a operacao '{action}'."
            }).encode("utf-8"))
            return

        if action == "UPLOAD_LAUDO":
            laudo_id = str(payload.get("laudo_id", "LAUDO_PADRAO")).strip()
            conteudo = str(payload.get("conteudo", "")).strip()
            client_hmac = str(payload.get("client_hmac", "")).strip()

            expected_client_hmac = hmac.new(HMAC_SECRET, conteudo.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(client_hmac, expected_client_hmac):
                logging.error(f"[INTEGRITY_FAIL] IP: {client_ip} | Laudo: {laudo_id} | HMAC de transito invalido!")
                conn.sendall(json.dumps({
                    "status": "ERRO_INTEGRIDADE",
                    "codigo": 422,
                    "mensagem": "Falha na verificacao de integridade HMAC-SHA256 do laudo enviado."
                }).encode("utf-8"))
                return

            rec = encrypt_and_store_laudo(laudo_id, conteudo, username)
            logging.info(
                f"[VAULT_STORE_OK] Laudo '{laudo_id}' cifrado com AES-256-GCM e salvo por '{username}'. "
                f"HMAC: {rec['hmac_sha256'][:16]}..."
            )
            conn.sendall(json.dumps({
                "status": "OK",
                "codigo": 201,
                "mensagem": f"Laudo '{laudo_id}' armazenado com cifragem AES-256-GCM e assinatura HMAC-SHA256.",
                "metadados_cofre": {
                    "laudo_id": rec["laudo_id"],
                    "algoritmo": rec["algoritmo"],
                    "nonce_hex": rec["nonce_hex"],
                    "ciphertext_preview": rec["ciphertext_hex"][:48] + "...",
                    "hmac_sha256": rec["hmac_sha256"]
                }
            }).encode("utf-8"))

        elif action == "LER_LAUDO":
            laudo_id = str(payload.get("laudo_id", "LAUDO_PADRAO")).strip()
            try:
                dados = decrypt_and_verify_laudo(laudo_id)
                logging.info(f"[VAULT_READ_OK] Laudo '{laudo_id}' verificado e decifrado para '{username}'.")
                conn.sendall(json.dumps({
                    "status": "OK",
                    "codigo": 200,
                    "dados_laudo": dados
                }).encode("utf-8"))
            except FileNotFoundError as fnf:
                conn.sendall(json.dumps({"status": "ERRO", "codigo": 404, "mensagem": str(fnf)}).encode("utf-8"))
            except ValueError as ve:
                logging.critical(f"[VAULT_TAMPER_DETECTED] {ve}")
                conn.sendall(json.dumps({"status": "ERRO_INTEGRIDADE", "codigo": 500, "mensagem": str(ve)}).encode("utf-8"))

    except socket.timeout:
        logging.warning(f"[TIMEOUT] Conexao expirada para {client_ip}")
    except ssl.SSLError as ssle:
        logging.error(f"[TLS_ERROR] Falha no handshake/canal TLS com {client_ip}: {ssle}")
    except Exception as e:
        logging.error(f"[SERVER_EXCEPTION] Erro inesperado com {client_ip}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(10)
        logging.info(f"=== SERVIDOR MEDVAULT-SEC INICIADO EM {HOST}:{PORT} (TLS ATIVO) ===")
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    handle_client(conn, addr)
                except ssl.SSLError as e:
                    logging.warning(f"[TLS_HANDSHAKE_FAIL] Conexao nao-TLS ou certificado rejeitado: {e}")
                except Exception as e:
                    logging.error(f"[ACCEPT_ERROR] {e}")

if __name__ == "__main__":
    main()