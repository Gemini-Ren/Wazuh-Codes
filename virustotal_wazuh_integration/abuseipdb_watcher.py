#!/bin/python3

import json
import urllib.request
import time

TOKEN = "SUA_API_KEY_VIRUSTOTAL"

alerts_file = "/var/ossec/logs/alerts/alerts.json"
output_log = "/var/log/virustotal_enriched.log"

TTL = 300
last_written = {}

def should_write(ip):
    now = time.time()
    if ip not in last_written or now - last_written[ip] > TTL:
        last_written[ip] = now
        return True
    return False

def lookup_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": TOKEN}

    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req, timeout=10)
        data = json.loads(response.read())
    except Exception:
        return

    data["event"] = "virustotal_lookup"
    data["src_ip"] = ip
    data["enriched_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    with open(output_log, "a") as f:
        f.write(json.dumps(data) + "\n")

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
