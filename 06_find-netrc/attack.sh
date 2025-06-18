#!/bin/bash
SEARCH_PATH=${1:-/}

echo "[*] Searching for .netrc files in $SEARCH_PATH..."

# Ищем файлы с именем .netrc
# find "$SEARCH_PATH" -type f -name ".netrc" 2>/dev/null -exec echo "[+] FOUND:" {} \; -exec cat {} \;
# Более надежный способ для вывода
find "$SEARCH_PATH" -type f -name ".netrc" 2>/dev/null | while read -r file; do
    echo "[+] FOUND: $file"
    echo "--- CONTENT ---"
    cat "$file"
    echo "---------------"
done

echo "[*] Search finished."
