# Используем базовый образ Ubuntu
FROM ubuntu:20.04

# Устанавливаем необходимые пакеты
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Проверяем наличие tcpdump или tshark
RUN if [ ! -x "$(command -v tcpdump)" ] && [ ! -x "$(command -v tshark)" ]; then exit 1; fi

# Устанавливаем рабочую директорию
WORKDIR /app

# Команда по умолчанию для запуска контейнера
CMD ["bash"]
