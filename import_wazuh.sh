#!/bin/bash

#######################################
# CONFIGURAÇÃO
#######################################

# Usuário e senha do Elasticsearch / OpenSearch
USER="USER"
PASS="PASSWORD"

# Endpoint do cluster
HOST="https://localhost:9200"

# Quantidade de linhas por lote enviado
BATCH=4000

#######################################

echo "==== Importador Wazuh ===="

# Pergunta diretório onde estão os logs
read -p "Diretório dos arquivos: " DIR

# Valida se diretório existe
[ ! -d "$DIR" ] && { echo "Diretório inválido"; exit 1; }

# Loop principal (permite importar vários arquivos)
while true
do
    echo
    echo "Arquivos disponíveis:"

    # Menu interativo para selecionar arquivo .gz
    select FILE in "$DIR"/ossec-alerts-*.json.gz "SAIR"; do
        [[ "$FILE" == "SAIR" ]] && exit 0
        [ -z "$FILE" ] && { echo "Escolha inválida"; continue; }
        break
    done

    echo
    echo "Arquivo escolhido → $FILE"

    #######################################
    # EXTRAIR DATA REAL DO LOG
    #######################################

    # Extrai primeira linha do arquivo e captura campo timestamp
    DATE=$(gunzip -c "$FILE" | head -1 | grep -oP '"timestamp":"\K[0-9\-]+' | head -1)

    # Se não encontrou data, cancela
    if [ -z "$DATE" ]; then
        echo "Não foi possível detectar data."
        continue
    fi

    # Converte data para formato de índice
    INDEX_DATE=$(echo "$DATE" | tr '-' '.')
    INDEX="wazuh-alerts-4.x-$INDEX_DATE"

    echo "Índice destino → $INDEX"

    #######################################
    # CHECAR SE ÍNDICE JÁ EXISTE
    #######################################

    # Consulta cluster para verificar existência
    EXISTS=$(curl -s -k -u $USER:$PASS "$HOST/$INDEX" | grep -c "$INDEX")

    if [ "$EXISTS" -gt 0 ]; then
        echo "Índice já existe."
        read -p "Reindexar mesmo assim? (s/n): " RESP
        [[ "$RESP" != "s" ]] && continue
    fi

    #######################################
    # PROCESSAMENTO
    #######################################

    # Cria pasta temporária
    TMP=$(mktemp -d)
    echo "Extraindo e dividindo..."

    # Descompacta e divide arquivo em partes menores
    gunzip -c "$FILE" | split -l $BATCH - "$TMP/part_"

    TOTAL=0

    # Loop para envio em lotes
    for f in "$TMP"/part_*; do

        # Conta linhas do lote
        COUNT=$(wc -l < "$f")
        TOTAL=$((TOTAL+COUNT))

        echo "Enviando lote ($COUNT docs)..."

        # Formata para bulk API e envia
        awk '{print "{\"index\":{}}\n"$0}' "$f" \
        | curl -s -k -u $USER:$PASS \
          -H "Content-Type: application/json" \
          -XPOST "$HOST/$INDEX/_bulk" \
          --data-binary @- \
        | grep -q '"errors":false'

        # Verifica retorno da API
        if [ $? -eq 0 ]; then
            echo "OK"
        else
            echo "ERRO NO LOTE"
        fi
    done

    #######################################
    # RESULTADO FINAL
    #######################################

    echo
    echo "Total enviado → $TOTAL"

    # Mostra contagem final do índice
    echo "Docs no índice:"
    curl -s -k -u $USER:$PASS "$HOST/$INDEX/_count?pretty"

    # Remove arquivos temporários
    rm -rf "$TMP"

    echo
    read -p "Importar outro arquivo? (s/n): " LOOP
    [[ "$LOOP" != "s" ]] && break
done

echo "Finalizado."
