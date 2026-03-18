"""
Script: Enriquecimento de dados usando o Virustotal
Autor: Renan Corrêa Sant'Anna
LinkedIn: https://www.linkedin.com/in/renan-sant-anna-11775116a
Data de criação: 17/03/2026
Descrição: Automação para monitorar alerts.json do Wazuh,
           extrair o campo 'data.srcip' e enriquecer informações
           de IP usando a API do Virustotal.
Versão: 1.0
"""

#!/bin/python3

import json
import urllib.request
import time

TOKEN = ""

alerts_file = "/var/ossec/logs/alerts/alerts.json"
output_log = "/var/log/virustotal_enriched.log"

# Tempo para permitir nova escrita do mesmo IP (em segundos)
TTL = 300  # 5 minutos

# Controle de escrita no log
last_written = {}

def should_write(ip):
    now = time.time()
    if ip not in last_written or now - last_written[ip] > TTL:
        last_written[ip] = now
        return True
    return False

def lookup_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": TOKEN
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req, timeout=5)
        data = json.loads(response.read())
    except Exception as e:
        print(f"Erro consultando {ip}: {e}")
        return

    attr = data.get("data", {}).get("attributes", {})

    # Última análise de reputação
    analysis = attr.get("last_analysis_stats", {})

    result = {
        "event": "virustotal_lookup",
        "ip": attr.get("last_https_certificate", {}).get("subject_alternative_name", [ip])[0],
        "asn": attr.get("asn"),
        "as_owner": attr.get("as_owner"),
        "country": attr.get("country"),
        "continent": attr.get("continent"),
        "network": attr.get("network"),
        "reputation": attr.get("reputation"),
        "last_analysis_stats": {
            "harmless": analysis.get("harmless"),
            "malicious": analysis.get("malicious"),
            "suspicious": analysis.get("suspicious"),
            "undetected": analysis.get("undetected"),
            "timeout": analysis.get("timeout")
        },
        "whois": attr.get("whois"),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(output_log, "a") as f:
        f.write(json.dumps(result) + "\n")

# Loop de leitura dos alerts.json
with open(alerts_file) as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(1)
            continue
        try:
            alert = json.loads(line)
        except:
            continue

        rule_id = str(alert.get("rule", {}).get("id"))
        if rule_id != "101202":
            continue

        ip = alert.get("data", {}).get("srcip")
        if ip and should_write(ip):
            lookup_ip(ip)
