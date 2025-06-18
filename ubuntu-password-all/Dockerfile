# Используем базовый образ Ubuntu
FROM ubuntu:latest

# Устанавливаем необходимые пакеты
RUN apt-get update && apt-get install -y \
    grep \
    && rm -rf /var/lib/apt/lists/*

# Копируем скрипт в контейнер
COPY script.sh /usr/local/bin/attack.sh

# Делаем скрипт исполняемым
RUN chmod +x /usr/local/bin/attack.sh

# Указываем команду по умолчанию
ENTRYPOINT ["/usr/local/bin/attack.sh"]
