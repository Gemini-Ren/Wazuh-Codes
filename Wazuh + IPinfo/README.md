Wazuh + IPinfo Integration (IP Enrichment)

Este projeto implementa uma automação de enriquecimento de alertas no Wazuh utilizando a API da IPinfo.

O objetivo é adicionar contexto automaticamente aos alertas, como ASN, organização e localização do IP, reduzindo o tempo de análise em ambientes de SOC.

📌 Visão Geral

Quando um alerta específico é gerado no Wazuh, o sistema:

Captura o evento em tempo real

Extrai o IP do alerta

Consulta a API do IPinfo

Gera um novo log enriquecido

O Wazuh processa esse log e cria um alerta enriquecido

🧠 Arquitetura
Suricata / Logs de rede
        ↓
Wazuh (rule 101202)
        ↓
alerts.json
        ↓
ipinfo_watcher.py
        ↓
Consulta IPinfo API
        ↓
/var/log/ipinfo_enriched.log
        ↓
Wazuh (decoder + rule)
        ↓
Alerta enriquecido
⚙️ Tecnologias utilizadas

Wazuh (SIEM / HIDS)

IPinfo (IP Intelligence API)

Python 3

JSON

Linux

🚀 Funcionalidades

Enriquecimento automático de IP

Processamento em tempo real de alertas

Integração via log (sem dependência do integrator)

Estrutura simples e escalável

Compatível com qualquer regra do Wazuh

📂 Estrutura do projeto
.
├── ipinfo_watcher.py
├── local_decoder.xml
├── local_rules.xml
└── README.md
🧪 Como funciona o script

O script:

Monitora continuamente o arquivo:

/var/ossec/logs/alerts/alerts.json

Filtra alertas com:

rule.id == 101202

Extrai o IP do campo:

data.srcip

Consulta a API:

https://api.ipinfo.io/lite/{ip}

Gera um log enriquecido em:

/var/log/ipinfo_enriched.log
📥 Instalação
1. Clonar o repositório
git clone https://github.com/seu-repo/wazuh-ipinfo.git
cd wazuh-ipinfo
2. Configurar o script

Edite o token da API:

TOKEN = "SEU_TOKEN"
3. Tornar executável
chmod +x ipinfo_watcher.py
4. Configurar o Wazuh
Adicionar no ossec.conf:
<localfile>
  <log_format>json</log_format>
  <location>/var/log/ipinfo_enriched.log</location>
</localfile>
5. Adicionar decoder
<decoder name="ipinfo">
  <prematch>"event":"ipinfo_lookup"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
6. Adicionar rule
<group name="ipinfo">

  <rule id="101300" level="6">
    <field name="event">ipinfo_lookup</field>
    <description>
      IP enrichment: $(ip) - $(country) - $(as_name)
    </description>
  </rule>

</group>
7. Reiniciar o Wazuh
systemctl restart wazuh-manager
8. Executar o script
python3 ipinfo_watcher.py

Ou configurar como serviço (systemd).

📊 Exemplo de saída
{
  "event": "ipinfo_lookup",
  "ip": "8.8.8.8",
  "asn": "AS15169",
  "as_name": "Google LLC",
  "country": "United States",
  "continent": "North America"
}
🔔 Exemplo de alerta no Wazuh
IP enrichment: 8.8.8.8 - United States - Google LLC
📈 Benefícios

Redução do tempo de análise

Mais contexto para decisões rápidas

Automação de tarefas repetitivas

Base para integração com Threat Intelligence

🔮 Melhorias futuras

Cache de IPs (evitar consultas repetidas)

Integração com:

AbuseIPDB

VirusTotal

Suporte a múltiplos campos (src/dst IP)

Paralelismo para alta escala

👨‍💻 Autor

Projeto desenvolvido para fins de estudo e aplicação prática em SOC.

📎 LinkedIn: (adicione aqui)

🛡️ Licença

Uso livre para estudos e melhorias.
