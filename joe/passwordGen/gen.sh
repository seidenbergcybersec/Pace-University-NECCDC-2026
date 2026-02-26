#!/bin/bash

# Get a truly random number from /dev/urandom
get_random_fixed() {
    # Returns a random number between 0 and ($1 - 1)
    echo $(( $(od -An -N2 -i /dev/urandom) % $1 ))
}

# Get a random number between 0-999
get_999() {
    echo $(( $(od -An -N2 -i /dev/urandom) % 1000 ))
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="${1:-$SCRIPT_DIR/wordlist.txt}"
NUM_WORDS=${2:-3}

# 1. Use shuf (which is generally secure) for the words
mapfile -t words < <(shuf -n "$NUM_WORDS" "$WORDLIST" | sed 's/./\U&/')

separators=("!" "@" "#" "$" "%" "^" "&" "*" "-" "_" "+" "=" ":")
# 2. Pick separator using urandom
sep_idx=$(get_random_fixed ${#separators[@]})
sep=${separators[$sep_idx]}

# 3. Start with random number
final_password="$(get_999)"

for word in "${words[@]}"; do
    rand_num="$(get_999)"
    # 4. Flip a coin using urandom for left/right placement
    if [[ $(( $(od -An -N1 -i /dev/urandom) % 2 )) -eq 0 ]]; then
        final_password+="${word}${rand_num}${sep}"
    else
        final_password+="${word}${sep}${rand_num}"
    fi
done

# 5. End with random number
final_password+="$(get_999)"

echo "$final_password"