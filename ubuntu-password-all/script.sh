#!/bin/bash

# Проверка наличия аргумента
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_file>"
    exit 1
fi

# Путь к файлу передан как аргумент
file_path="$1"

# Выполнение команды grep для поиска паролей
grep -ri password "$file_path"

# Завершение скрипта
exit 0
