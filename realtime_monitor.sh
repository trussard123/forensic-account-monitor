#!/bin/bash

# ============================================================
# REAL-TIME Zero-Latency Forensic Monitor
# Kraemer Forensic Evidence Collection
# 20-50 foot RSSI Proximity Trap + MAC Harvester
# Distinguishes new captures from repeat offenders
# No sound — Pushover alerts only
# ============================================================

PUSHOVER_TOKEN="abne6i1wxa1rrhqgfzej6yuz2dvxoi"
PUSHOVER_USER="u3jt3rm8cfdtkko32jg8yrabvw4zmy"

LOG_DIR="$HOME/Documents/forensic_monitor"
LIVE_LOG="$LOG_DIR/LIVE_STREAM.log"
MAC_LOG="$LOG_DIR/MAC_HARVEST.log"
PROXIMITY_LOG="$LOG_DIR/PROXIMITY.log"
ALL_SEEN_FILE="$LOG_DIR/.all_seen_tokens"
LAST_RSSI_FILE="$LOG_DIR/.last_rssi_alert"

RSSI_APPROACH=80
RSSI_COOLDOWN=30
OWN_DEVICES="9CC441C0|f8:73:df:1d:dc:f6|8a:1e:5a:99:ab:67|BBEsZeOh"

mkdir -p "$LOG_DIR"
touch "$ALL_SEEN_FILE"
touch "$LAST_RSSI_FILE"

pushover_alert() {
    local TITLE="$1"
    local MESSAGE="$2"
    local PRIORITY="$3"
    if [ "$PRIORITY" = "2" ]; then
        curl -s \
            -d "token=$PUSHOVER_TOKEN" \
            -d "user=$PUSHOVER_USER" \
            -d "title=$TITLE" \
            -d "message=$MESSAGE" \
            -d "priority=2" \
            -d "retry=30" \
            -d "expire=300" \
            https://api.pushover.net/1/messages.json > /dev/null
    else
        curl -s \
            -d "token=$PUSHOVER_TOKEN" \
            -d "user=$PUSHOVER_USER" \
            -d "title=$TITLE" \
            -d "message=$MESSAGE" \
            -d "priority=$PRIORITY" \
            https://api.pushover.net/1/messages.json > /dev/null
    fi
}

rssi_cooldown_passed() {
    local LAST=$(cat "$LAST_RSSI_FILE" 2>/dev/null || echo 0)
    local NOW=$(date +%s)
    local DIFF=$((NOW - LAST))
    if [ "$DIFF" -gt "$RSSI_COOLDOWN" ]; then
        echo "$NOW" > "$LAST_RSSI_FILE"
        return 0
    fi
    return 1
}

echo "$(date) — Real-time monitor started" >> "$LIVE_LOG"
echo "$(date) — Real-time monitor started" >> "$PROXIMITY_LOG"
echo "Monitoring... Press Ctrl+C to stop"
echo "RSSI threshold: Approach=-${RSSI_APPROACH} (20-50 feet)"

TARGET_NODES=("BBvdpKri" "BBDfoyVs" "EEB54B57" "BBMjQHOv" "BBECrnNp" "BBKykGmT")

# ============================================================
# STREAM 1 — RSSI Proximity Trap (rapportd) 20-50 feet only
# ============================================================
log stream --info \
    --predicate 'process == "rapportd"' \
    2>/dev/null | \
grep --line-buffered "RSSI" | \
while IFS= read -r LINE; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$LINE" | grep -qE "$OWN_DEVICES" && continue
    RSSI_RAW=$(echo "$LINE" | grep -oE "RSSI -[0-9]+" | head -1)
    [ -z "$RSSI_RAW" ] && continue
    RSSI_NUM=$(echo "$RSSI_RAW" | grep -oE "[0-9]+")
    IDS=$(echo "$LINE" | grep -oE "IDS '[A-Za-z0-9]+'" | head -1)
    echo "$TIMESTAMP | $RSSI_RAW | $IDS" >> "$PROXIMITY_LOG"
    echo "$LINE" | grep -qE "SameAccountDevice|BBKykGmT|BBECrnNp|DeviceAuthTag|PairVerify" || continue
    if [ "$RSSI_NUM" -le "$RSSI_APPROACH" ]; then
        if rssi_cooldown_passed; then
            pushover_alert "APPROACH DETECTED" "$RSSI_RAW | 20-50 feet | $IDS | $TIMESTAMP" "0"
            echo "$TIMESTAMP | APPROACH | $RSSI_RAW | $IDS" >> "$PROXIMITY_LOG"
        fi
    else
        echo "$TIMESTAMP | DISTANT | $RSSI_RAW | $IDS" >> "$PROXIMITY_LOG"
    fi
done &

# ============================================================
# STREAM 2 — Authentication Monitor (rapportd only)
# ============================================================
log stream --info \
    --predicate 'process == "rapportd"' \
    2>/dev/null | \
grep --line-buffered "SameAccountDevice" | \
while IFS= read -r LINE; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$LINE" | grep -qE "$OWN_DEVICES" && continue
    echo "$TIMESTAMP | $LINE" >> "$LIVE_LOG"
    LINE_TOKENS=$(echo "$LINE" | grep -oE "(IDS|AID|MRI|MRtI|AltDSID|AccountAltDSID) '[A-Za-z0-9]+'")
    NEW_FOUND=""
    while IFS= read -r TOKEN; do
        [ -z "$TOKEN" ] && continue
        if ! grep -qF "$TOKEN" "$ALL_SEEN_FILE"; then
            NEW_FOUND="$NEW_FOUND $TOKEN"
            echo "$TIMESTAMP | NEW TOKEN: $TOKEN | $LINE" >> "$LIVE_LOG"
            echo "$TOKEN" >> "$ALL_SEEN_FILE"
        fi
    done <<< "$LINE_TOKENS"
    TARGETS_HIT=""
    for NODE in "${TARGET_NODES[@]}"; do
        if echo "$LINE" | grep -q "$NODE"; then
            TARGETS_HIT="$TARGETS_HIT $NODE"
        fi
    done
    IS_OWNER=$(echo "$LINE" | grep -c "AcLv = User (11)" || true)
    IS_BATCH=$(echo "$LINE" | grep -c "Added same account identity" || true)
    IS_PAIRVERIFY=$(echo "$LINE" | grep -c "PairVerifyVerify success" || true)
    if [ -n "$TARGETS_HIT" ]; then
        pushover_alert "EMERGENCY: KNOWN TARGET" "Target:$TARGETS_HIT | $TIMESTAMP" "2"
    elif [ "$IS_BATCH" -gt 0 ]; then
        pushover_alert "EMERGENCY: BATCH DEPLOYMENT" "New identities loaded | $TIMESTAMP" "2"
    elif [ "$IS_OWNER" -gt 0 ]; then
        pushover_alert "OWNER ACCESS — VIOLATION CONFIRMED" "AcLv User(11) | $TIMESTAMP" "1"
    elif [ "$IS_PAIRVERIFY" -gt 0 ]; then
        pushover_alert "PairVerify — VIOLATION LOGGED" "$TIMESTAMP | $(echo $LINE | cut -c1-80)" "0"
    fi
    if [ -n "$NEW_FOUND" ]; then
        pushover_alert "NEW TEAM DETECTED" "Tokens:$NEW_FOUND | $TIMESTAMP" "1"
    fi
done &

# ============================================================
# STREAM 3 — MAC Harvester + DirectLink + Repeat Offender
# ============================================================
log stream --info \
    --predicate 'process == "rapportd"' \
    2>/dev/null | \
grep --line-buffered "DeviceAuthTag" | \
while IFS= read -r LINE; do
    echo "$LINE" | grep -qE "$OWN_DEVICES" && continue
    MAC=$(echo "$LINE" | grep -oE "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | head -1)
    if [ -n "$MAC" ]; then
        TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
        IS_DIRECT=$(echo "$LINE" | grep -c "DirectLink" || true)
        CONN_TYPE="AWDL"
        [ "$IS_DIRECT" -gt 0 ] && CONN_TYPE="DirectLink-CLOSE"
        DEV_NAME=$(echo "$LINE" | grep -oE '"[^"]*"' | head -1)
        IDS=$(echo "$LINE" | grep -oE "IDS '[A-Za-z0-9]+'" | head -1)

        # Count prior appearances of this MAC
        REPEAT_COUNT=$(grep -c "$MAC" "$MAC_LOG" 2>/dev/null || echo 0)

        # Log the event
        echo "$TIMESTAMP | MAC: $MAC | $CONN_TYPE | Count: $((REPEAT_COUNT + 1)) | $DEV_NAME | $LINE" >> "$MAC_LOG"

        # Alert — distinguish new capture from re-authentication
        if [ "$REPEAT_COUNT" -eq 0 ]; then
            pushover_alert "NEW MAC CAPTURED" "MAC: $MAC | $CONN_TYPE | $IDS | $DEV_NAME | $TIMESTAMP" "1"
        else
            pushover_alert "RE-AUTHENTICATION — REPEAT OFFENDER" "MAC: $MAC | Seen: $((REPEAT_COUNT + 1))x | $CONN_TYPE | $IDS | $TIMESTAMP" "1"
        fi
    fi
done &

# ============================================================
# STREAM 4 — BLE Early Warning (bluetoothd) 20-50 feet only
# ============================================================
log stream --info \
    --predicate 'process == "bluetoothd"' \
    2>/dev/null | \
grep --line-buffered "RSSI" | \
while IFS= read -r LINE; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$LINE" | grep -qE "$OWN_DEVICES" && continue
    RSSI_RAW=$(echo "$LINE" | grep -oE "RSSI -[0-9]+" | head -1)
    [ -z "$RSSI_RAW" ] && continue
    RSSI_NUM=$(echo "$RSSI_RAW" | grep -oE "[0-9]+" | head -1)
    [ -z "$RSSI_NUM" ] && continue
    DEVICE=$(echo "$LINE" | grep -oE "CBDevice [A-Z0-9-]+" | head -1)
    CHANNEL=$(echo "$LINE" | grep -oE "Ch [0-9]+" | head -1)
    NBIF=$(echo "$LINE" | grep -oE "nbIF [^ ]+" | head -1)
    echo "$TIMESTAMP | BLE | $RSSI_RAW | $DEVICE | $CHANNEL | $NBIF" >> "$PROXIMITY_LOG"
    if [ "$RSSI_NUM" -le "$RSSI_APPROACH" ]; then
        if rssi_cooldown_passed; then
            pushover_alert "BLE APPROACH — HEADS UP" "BLE $RSSI_RAW | 20-50 feet | $DEVICE | $NBIF | $TIMESTAMP" "0"
            echo "$TIMESTAMP | BLE APPROACH | $RSSI_RAW | $DEVICE" >> "$PROXIMITY_LOG"
        fi
    fi
done &

wait