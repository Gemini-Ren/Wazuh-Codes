"""
Script: wazuh_ipinfo_integration.py
Autor: Renan Corrêa Sant'Anna
LinkedIn: https://www.linkedin.com/in/renan-sant-anna-11775116a
Data de criação: 17/03/2026
Descrição: Automação para monitorar alerts.json do Wazuh,
           extrair o campo 'data.srcip' e enriquecer informações
           de IP usando a API do IPinfo.
Versão: 1.0
"""

#!/bin/python3

import json
import urllib.request
import time

TOKEN = "SEU_TOKEN"

alerts_file = "/var/ossec/logs/alerts/alerts.json"
output_log = "/var/log/ipinfo_enriched.log"

def lookup_ip(ip):

    url = f"https://api.ipinfo.io/lite/{ip}?token={TOKEN}"

    try:
        response = urllib.request.urlopen(url, timeout=5)
        data = json.loads(response.read())
    except:
        return

    result = {
        "event": "ipinfo_lookup",
        "ip": data.get("ip"),
        "asn": data.get("asn"),
        "as_name": data.get("as_name"),
        "country": data.get("country"),
        "continent": data.get("continent")
    }

    with open(output_log, "a") as f:
        f.write(json.dumps(result) + "\n")

with open(alerts_file) as f:

    f.seek(0,2)

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

        if ip:
            lookup_ip(ip)
