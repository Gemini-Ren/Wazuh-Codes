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

--------------------------------------------------------------------------------

📂 Estrutura do projeto
.
├── ipinfo_watcher.py
├── local_decoder.xml
├── local_rules.xml
└── README.md

--------------------------------------------------------------------------------

🧪 Como funciona o script
git clone https://github.com/seu-repo/wazuh-ipinfo.git
cd wazuh-ipinfo

👨‍💻 Autor

Projeto desenvolvido para fins de estudo e aplicação prática em SOC.

📎 LinkedIn:  https://www.linkedin.com/in/renan-sant-anna-11775116a

🛡️ Licença

Uso livre para estudos e melhorias.
