#!/bin/bash

# Проверка наличия аргумента
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_search>"
    exit 1
fi

search_path="$1"

echo "[*] Searching for 'password' string in directory: $search_path"

# Выполнение команды grep для поиска паролей, игнорируя ошибки доступа
grep -rni "password" "$search_path" 2>/dev/null || echo "[-] No files with 'password' found."

echo "[*] Search finished."
exit 0
