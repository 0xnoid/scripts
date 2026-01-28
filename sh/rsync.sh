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
NC='\033[0m'
BOLD='\033[1m'

[ -f "$CACHE_FILE" ] && source "$CACHE_FILE"

read -p "Username [$LAST_USER]: " USER
USER=${USER:-$LAST_USER}

read -p "Host [$LAST_HOST]: " HOST
HOST=${HOST:-$LAST_HOST}

read -p "Remote path [$LAST_PATH]: " REMOTE_PATH
REMOTE_PATH=${REMOTE_PATH:-$LAST_PATH}

if [[ -z "$USER" || -z "$HOST" || -z "$REMOTE_PATH" ]]; then
    echo -e "${RED}Error: All fields are required${NC}"
    exit 1
fi

cat > "$CACHE_FILE" << EOF
LAST_USER="$USER"
LAST_HOST="$HOST"
LAST_PATH="$REMOTE_PATH"
EOF

LOCAL_PATH="$USER"
mkdir -p "$LOCAL_PATH"
LOG_FILE=$(mktemp)

if [ "$MODE" = "down" ]; then
    SRC="${USER}@${HOST}:${REMOTE_PATH}/" 
    DEST="${LOCAL_PATH}/"
    DIRECTION="${BLUE}${REMOTE_PATH}${NC} ${YELLOW}→${NC} ${GREEN}${LOCAL_PATH}${NC}"
else
    SRC="${LOCAL_PATH}/"
    DEST="${USER}@${HOST}:${REMOTE_PATH}/"
    DIRECTION="${GREEN}${LOCAL_PATH}${NC} ${YELLOW}→${NC} ${BLUE}${REMOTE_PATH}${NC}"
fi

echo -e "\n${BOLD}Starting transfer...${NC}"
echo -e "$DIRECTION\n"
rsync -avz --info=progress2 --no-inc-recursive --stats "$SRC" "$DEST" > "$LOG_FILE" 2>&1 &
RSYNC_PID=$!
tput civis
trap "tput cnorm; rm -f $LOG_FILE; exit" INT TERM EXIT

while kill -0 $RSYNC_PID 2>/dev/null; do
    PROGRESS_LINE=$(tail -n 2 "$LOG_FILE" | grep "%" | tail -n 1)
    
    if [[ "$PROGRESS_LINE" =~ ([0-9]+)% ]]; then
        PERCENT="${BASH_REMATCH[1]}"
        COLS=$(tput cols)
        BAR_WIDTH=$((COLS - 20))
        [ $BAR_WIDTH -lt 10 ] && BAR_WIDTH=10
        FILLED=$((PERCENT * BAR_WIDTH / 100))
        EMPTY=$((BAR_WIDTH - FILLED))
        BAR_STR=$(printf "%0.s█" $(seq 1 $FILLED))
        PAD_STR=$(printf "%0.s░" $(seq 1 $EMPTY))
        COLOR="$BLUE"
        [ "$PERCENT" -eq 100 ] && COLOR="$GREEN"
        
        printf "\r${COLOR}[%s%s] %3d%%${NC}" "$BAR_STR" "$PAD_STR" "$PERCENT"
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
        else if (bytes < 5242880) printf "%.2f KB", bytes/1024;  # Less than 5MB show KB
        else printf "%.2f MB", bytes/1048576;                     # Else show MB
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
