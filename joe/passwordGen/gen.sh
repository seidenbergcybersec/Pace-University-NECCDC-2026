#!/bin/bash

# Get a truly random number from /dev/urandom
get_random_fixed() {
    echo $(( $(od -An -N2 -i /dev/urandom) % $1 ))
}

# Get a random number between 0-999
get_999() {
    echo $(( $(od -An -N2 -i /dev/urandom) % 1000 ))
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="${SCRIPT_DIR}/wordlist.txt"
NUM_WORDS=3
LOG_FILE="$SCRIPT_DIR/passwords.log"

# Parse arguments
PASSWORD_NAME="${1:-unnamed}"
PASSWORD_NOTE="${2:-}"

separators=("!" "@" "#" "$" "%" "^" "&" "*" "-" "_" "+" "=" ":")
sep_idx=$(get_random_fixed ${#separators[@]})
sep=${separators[$sep_idx]}

mapfile -t words < <(shuf -n "$NUM_WORDS" "$WORDLIST" | sed 's/./\U&/')

final_password="$(get_999)"

for word in "${words[@]}"; do
    rand_num="$(get_999)"
    if [[ $(( $(od -An -N1 -i /dev/urandom) % 2 )) -eq 0 ]]; then
        final_password+="${word}${rand_num}${sep}"
    else
        final_password+="${word}${sep}${rand_num}"
    fi
done

final_password+="$(get_999)"

# Append to log file
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
if [[ ! -f "$LOG_FILE" ]]; then
    printf "%-20s %-19s %-60s %s\n" "NAME" "GENERATED AT" "PASSWORD" "NOTE" >> "$LOG_FILE"
    printf "%-20s %-19s %-60s %s\n" "----" "------------" "--------" "----" >> "$LOG_FILE"
fi

printf "%-20s %-19s %-60s %s\n" "$PASSWORD_NAME" "$TIMESTAMP" "$final_password" "$PASSWORD_NOTE" >> "$LOG_FILE"

echo "$final_password"