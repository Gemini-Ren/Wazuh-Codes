# Wazuh + AbuseIPDB Enrichment

Este projeto realiza o enriquecimento automático de alertas do Wazuh utilizando a API do AbuseIPDB.

## Arquitetura

Wazuh alerta → Script Python → AbuseIPDB → Log enriquecido → Wazuh → Rule

## Instalação

1. Copiar script:
cp abuseipdb_watcher.py /usr/local/bin/
chmod +x /usr/local/bin/abuseipdb_watcher.py

2. Configurar API Key no script

3. Adicionar no ossec.conf:

<localfile>
  <log_format>json</log_format>
  <location>/var/log/abuseipdb_enriched.log</location>
</localfile>

4. Copiar decoder e rule

5. Reiniciar:
systemctl restart wazuh-manager
