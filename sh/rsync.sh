#!/bin/bash
# Rsync is great as it is, so what's the purpose? To make manual server migrations or backups easier.
## Allows simple input: user, host, hostpath (download) /localpath (upload)
### Usage: Add script to '~/bin/rsync.sh' and make executable, then add this to ~/.bashrc and use either 'rsync down' (download) or 'rsync up' (upload)
#### export PATH="$HOME/bin:$PATH"
#### rsync() {
####     if [[ "$1" == "up" || "$1" == "down" ]]; then
####         ~/bin/rsync.sh "$1"
####     else
####         command rsync "$@"
####     fi
#### }

#!/bin/bash

CACHE_DIR="$HOME/.cache/rsync"
mkdir -p "$CACHE_DIR"

MODE="$1"
if [[ "$MODE" != "up" && "$MODE" != "down" ]]; then
    echo "Usage: rsync.sh [up|down]"
    exit 1
fi

CACHE_FILE="$CACHE_DIR/${MODE}_last"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

[ -f "$CACHE_FILE" ] && source "$CACHE_FILE"

echo -e "${GREY}Tip: Type '#!' to edit the previous value${NC}\n"

while true; do
    read -p "Username [$LAST_USER]: " USER
    USER=$(echo "$USER" | tr -d '\n\r' | xargs)
    
    if [[ "$USER" == "#!" ]]; then
        read -e -i "$LAST_USER" -p "Username: " USER
        USER=$(echo "$USER" | tr -d '\n\r' | xargs)
    fi
    USER=${USER:-$LAST_USER}
    break
done

while true; do
    read -p "Host [$LAST_HOST]: " HOST
    HOST=$(echo "$HOST" | tr -d '\n\r' | xargs)
    
    if [[ "$HOST" == "#!" ]]; then
        read -e -i "$LAST_HOST" -p "Host: " HOST
        HOST=$(echo "$HOST" | tr -d '\n\r' | xargs)
    fi
    HOST=${HOST:-$LAST_HOST}
    break
done

while true; do
    read -p "Remote path [$LAST_PATH]: " REMOTE_PATH
    REMOTE_PATH=$(echo "$REMOTE_PATH" | tr -d '\n\r' | xargs)
    
    if [[ "$REMOTE_PATH" == "#!" ]]; then
        read -e -i "$LAST_PATH" -p "Remote path: " REMOTE_PATH
        REMOTE_PATH=$(echo "$REMOTE_PATH" | tr -d '\n\r' | xargs)
    fi
    REMOTE_PATH=${REMOTE_PATH:-$LAST_PATH}
    break
done

if [ "$MODE" = "up" ]; then
    while true; do
        read -p "Local path [$LAST_LOCAL]: " LOCAL_PATH
        LOCAL_PATH=$(echo "$LOCAL_PATH" | tr -d '\n\r' | xargs)
        
        if [[ "$LOCAL_PATH" == "#!" ]]; then
            read -e -i "$LAST_LOCAL" -p "Local path: " LOCAL_PATH
            LOCAL_PATH=$(echo "$LOCAL_PATH" | tr -d '\n\r' | xargs)
        fi
        LOCAL_PATH=${LOCAL_PATH:-$LAST_LOCAL}
        break
    done
    
    LOCAL_PATH="${LOCAL_PATH/#\~/$HOME}"
    
    if [[ ! "$LOCAL_PATH" = /* ]]; then
        LOCAL_PATH="$(pwd)/$LOCAL_PATH"
    fi
    
    if [[ ! -d "$LOCAL_PATH" ]]; then
        echo -e "\n${RED}Error: Local path does not exist: $LOCAL_PATH${NC}"
        exit 1
    fi
else
    LOCAL_PATH="$USER"
fi

if [[ -z "$USER" || -z "$HOST" || -z "$REMOTE_PATH" ]]; then
    echo -e "\n${RED}Error: All fields are required${NC}"
    exit 1
fi

cat > "$CACHE_FILE" << EOF
LAST_USER="$USER"
LAST_HOST="$HOST"
LAST_PATH="$REMOTE_PATH"
LAST_LOCAL="$LOCAL_PATH"
EOF

if [ "$MODE" = "down" ]; then
    mkdir -p "$LOCAL_PATH"
fi

LOG_FILE=$(mktemp)

echo -e "\n${YELLOW}Preflight: Testing for SSH keys${NC}"

ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "${USER}@${HOST}" "exit" 2>/dev/null
SSH_KEY_TEST=$?

if [ $SSH_KEY_TEST -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully matched SSH key${NC}"
else
    echo -e "${RED}✗ Failed to match SSH key for ${BLUE}${HOST}${NC}${RED} - Using password${NC}"
fi

if [ "$MODE" = "down" ]; then
    SRC="${USER}@${HOST}:${REMOTE_PATH}/"
    DEST="${LOCAL_PATH}/"
    DIRECTION="${BLUE}${REMOTE_PATH}${NC} ${YELLOW}→${NC} ${GREEN}${LOCAL_PATH}${NC}"
else
    SRC="${LOCAL_PATH}/"
    DEST="${USER}@${HOST}:${REMOTE_PATH}/"
    DIRECTION="${GREEN}${LOCAL_PATH}${NC} ${YELLOW}→${NC} ${BLUE}${USER}@${HOST}:${REMOTE_PATH}${NC}"
fi

echo -e "${BOLD}Starting transfer...${NC}"
echo -e "$DIRECTION"

rsync -avz --info=progress2 --no-inc-recursive --stats "$SRC" "$DEST" > "$LOG_FILE" 2>&1 &
RSYNC_PID=$!

tput civis
trap "tput cnorm; rm -f $LOG_FILE; exit" INT TERM EXIT

while kill -0 $RSYNC_PID 2>/dev/null; do
    PROGRESS_LINE=$(tail -n 3 "$LOG_FILE" 2>/dev/null | grep -E '[0-9]+%' | tail -n 1)

    if [[ "$PROGRESS_LINE" =~ [^0-9]*([0-9,]+)[^0-9]+([0-9]+)% ]]; then
        CURRENT_BYTES=$(echo "${BASH_REMATCH[1]}" | tr -d ',')
        PERCENT="${BASH_REMATCH[2]}"

        if [ "$PERCENT" -gt 0 ]; then
            TOTAL_BYTES=$((CURRENT_BYTES * 100 / PERCENT))
        else
            TOTAL_BYTES=$CURRENT_BYTES
        fi

        CURRENT_SIZE=$(awk -v bytes="$CURRENT_BYTES" 'BEGIN {
            if (bytes < 1048576) printf "%.0fKB", bytes/1024;
            else printf "%.0fMB", bytes/1048576;
        }')

        TOTAL_SIZE=$(awk -v bytes="$TOTAL_BYTES" 'BEGIN {
            if (bytes < 1048576) printf "%.0fKB", bytes/1024;
            else printf "%.0fMB", bytes/1048576;
        }')

        COLS=$(tput cols)
        INFO_WIDTH=35
        BAR_WIDTH=$((COLS - INFO_WIDTH))
        [ $BAR_WIDTH -lt 20 ] && BAR_WIDTH=20

        FILLED=$((PERCENT * BAR_WIDTH / 100))
        EMPTY=$((BAR_WIDTH - FILLED))

        BAR_STR=$(printf "%0.s█" $(seq 1 $FILLED))
        PAD_STR=$(printf "%0.s░" $(seq 1 $EMPTY))

        COLOR="$BLUE"
        [ "$PERCENT" -eq 100 ] && COLOR="$GREEN"

        printf "\r${COLOR}[%s%s]${NC} %3d%% [${BLUE}%s${NC}/${GREEN}%s${NC}]" "$BAR_STR" "$PAD_STR" "$PERCENT" "$CURRENT_SIZE" "$TOTAL_SIZE"
    fi
    sleep 0.1
done
wait $RSYNC_PID
RSYNC_EXIT=$?
tput cnorm
echo ""

OUTPUT=$(cat "$LOG_FILE")

if [ $RSYNC_EXIT -eq 0 ]; then
    FILE_COUNT=$(echo "$OUTPUT" | grep "Number of regular files transferred:" | awk '{print $6}' | tr -d ',')
    TOTAL_BYTES=$(echo "$OUTPUT" | grep "Total transferred file size:" | awk '{print $5}' | tr -d ',')

    READABLE_SIZE=$(awk -v bytes="$TOTAL_BYTES" 'BEGIN {
        if (bytes < 1024) printf "%d B", bytes;
        else if (bytes < 5242880) printf "%.2f KB", bytes/1024;
        else printf "%.2f MB", bytes/1048576;
    }')

    echo -e "\n${GREEN}${BOLD}Transfer Success:${NC}"
    if [ "$MODE" = "down" ]; then
        echo -e "${BLUE}${USER}@${HOST}:${REMOTE_PATH}${NC} ${YELLOW}→${NC} ${GREEN}${LOCAL_PATH}${NC}"
    else
        echo -e "${GREEN}${LOCAL_PATH}${NC} ${YELLOW}→${NC} ${BLUE}${USER}@${HOST}:${REMOTE_PATH}${NC}"
    fi
    echo -e "${CYAN}${FILE_COUNT:-0} files${NC}"
    echo -e "${CYAN}${READABLE_SIZE:-0 B}${NC}\n"

else
    echo -e "\n${RED}${BOLD}Transfer Failed:${NC}"
    ERR_MSG=$(echo "$OUTPUT" | grep -v "%" | grep -v "sent" | grep -v "total size")
    echo -e "${RED}${ERR_MSG}${NC}\n"
fi
