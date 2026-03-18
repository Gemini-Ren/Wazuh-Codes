# Wazuh + VirusTotal Enrichment

## Descrição
Integração para enriquecimento de alertas do Wazuh utilizando a API do VirusTotal.
O script monitora o arquivo `alerts.json`, extrai IPs de eventos específicos e consulta o VirusTotal, registrando o JSON completo para posterior análise e correlação.

## Componentes
- **abuseipdb_watcher.py**: Script Python responsável pelo enrichment
- **decoder.xml**: Decoder para interpretar os logs JSON
- **rule.xml**: Regras de detecção baseadas nos dados enriquecidos
- **ossec.conf**: Configuração para ingestão do log enriquecido

## Funcionamento
1. Wazuh gera alertas (`alerts.json`)
2. Script monitora eventos com `rule.id = 101202`
3. IP é extraído (`srcip`)
4. Consulta na API do VirusTotal
5. JSON completo é salvo em `/var/log/virustotal_enriched.log`
6. Wazuh lê, decodifica e aplica regras

## Requisitos
- Python 3
- API Key do VirusTotal
- Wazuh Manager ativo

## Execução
```bash
chmod +x virustotal_watcher.py
./abuseipdb_watcher.py
```

## Teste
```bash
echo '{"event":"virustotal_lookup","src_ip":"8.8.8.8"}' >> /var/log/virustotal_enriched.log
```

## Observações
- Utiliza TTL para evitar consultas repetidas
- Mantém JSON completo para máxima visibilidade
