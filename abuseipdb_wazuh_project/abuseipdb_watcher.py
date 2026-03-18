"""
Script: Enriquecimento de dados usando ABUSEIPDB
Autor: Renan Corrêa Sant'Anna
LinkedIn: https://www.linkedin.com/in/renan-sant-anna-11775116a
Data de criação: 17/03/2026
Descrição: Automação para monitorar alerts.json do Wazuh,
           extrair o campo 'data.srcip' e enriquecer informações
           de IP usando a API do ABUSEIPDB.
Versão: 1.0
"""

#!/bin/python3

import json
import urllib.request
import time

API_KEY = "SUA_API_KEY_AQUI"

alerts_file = "/var/ossec/logs/alerts/alerts.json"
output_log = "/var/log/abuseipdb_enriched.log"

TTL = 300
last_written = {}

def should_write(ip):
    now = time.time()
    if ip not in last_written:
        last_written[ip] = now
        return True
    if now - last_written[ip] > TTL:
        last_written[ip] = now
        return True
    return False

def lookup_ip(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url)
    req.add_header("Key", API_KEY)
    req.add_header("Accept", "application/json")

    try:
        response = urllib.request.urlopen(req, timeout=5)
        data = json.loads(response.read())
    except:
        return

    abuse_data = data.get("data", {})

    result = {
        "event": "abuseipdb_lookup",
        "ip": abuse_data.get("ipAddress"),
        "abuse_score": abuse_data.get("abuseConfidenceScore"),
        "country": abuse_data.get("countryCode"),
        "isp": abuse_data.get("isp"),
        "domain": abuse_data.get("domain"),
        "usage_type": abuse_data.get("usageType"),
        "total_reports": abuse_data.get("totalReports"),
        "distinct_users": abuse_data.get("numDistinctUsers"),
        "last_reported": abuse_data.get("lastReportedAt"),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(output_log, "a") as f:
        f.write(json.dumps(result) + "\n")

def main():
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

if __name__ == "__main__":
    main()
