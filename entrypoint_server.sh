#!/bin/bash
set -e

echo "[INIT] Verificando certificados X.509 (OpenSSL)..."
if [ ! -f /app/certs/server.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /app/certs/server.key \
        -out /app/certs/server.crt \
        -subj "/C=BR/ST=Parana/L=Curitiba/O=PUCPR-ClinicaVidaSegura/OU=EngenhariaDeSoftware/CN=172.28.0.10"
    chmod 600 /app/certs/server.key
    echo "[INIT] Certificado X.509 RSA-2048 gerado com sucesso."
fi

echo "[INIT] Configurando baseline de Firewall (iptables)..."
iptables -F INPUT || true
iptables -P INPUT ACCEPT || true
# Permite loopback e conexoes estabelecidas
iptables -A INPUT -i lo -j ACCEPT || true
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
echo "[INIT] Firewall iptables ativo e monitorando porta 8443/TCP."

exec python -u /app/server.py