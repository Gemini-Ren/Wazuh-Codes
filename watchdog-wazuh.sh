#!/bin/bash

#################################
# WAZUH AUTO HEAL WATCHDOG
#################################

LOG="/var/log/wazuh-autoheal.log"
LOCK="/tmp/wazuh-restart.lock"

DATE=$(date "+%Y-%m-%d %H:%M:%S")

YEAR=$(date +%Y)
MONTH=$(date +%b)
DAY=$(date +%d)

ALERT_FILE="/var/ossec/logs/alerts/$YEAR/$MONTH/ossec-alerts-$DAY.json"

echo "[$DATE] Checking ingestion..." >> $LOG

#################################
# 1 — IGNORAR ROTAÇÃO 00:00
#################################

HOUR=$(date +%H)
MIN=$(date +%M)

if [[ "$HOUR" == "00" && "$MIN" -lt 5 ]]; then
    echo "[$DATE] Midnight rotation window — skipping check" >> $LOG
    exit 0
fi

#################################
# 2 — VERIFICAR EXISTÊNCIA
#################################

if [ ! -f "$ALERT_FILE" ]; then
    echo "[$DATE] Alert file not found" >> $LOG
    exit 0
fi

#################################
# 3 — TAMANHO DO ARQUIVO
#################################

SIZE_NOW=$(stat -c%s "$ALERT_FILE")

sleep 60

SIZE_AFTER=$(stat -c%s "$ALERT_FILE")

#################################
# 4 — DETECTAR PARADA REAL
#################################

if [ "$SIZE_NOW" -eq "$SIZE_AFTER" ]; then

    echo "[$DATE] ⚠️ Log not growing!" >> $LOG

    #################################
    # LOCK ANTI LOOP (30 min)
    #################################

    if [ -f "$LOCK" ]; then
        LAST_RESTART=$(stat -c %Y "$LOCK")
        NOW=$(date +%s)

        if (( NOW - LAST_RESTART < 1800 )); then
            echo "[$DATE] Restart skipped (lock active)" >> $LOG
            exit 0
        fi
    fi

    touch $LOCK

    echo "[$DATE] 🚑 Restarting Wazuh Stack..." >> $LOG

    systemctl restart wazuh-manager
    sleep 20

    systemctl restart filebeat
    sleep 20

    systemctl restart wazuh-indexer

    echo "[$DATE] ✅ Restart executed" >> $LOG

else
    echo "[$DATE] ✅ Ingestion OK" >> $LOG
fi
