# Используем официальный образ GCC для компиляции
FROM gcc:12.2.0

# Устанавливаем sudo и создаем пользователя с правами
RUN apt-get update && \
    apt-get install -y sudo && \
    useradd -m -s /bin/bash attacker && \
    echo "attacker:attackerpass" | chpasswd && \
    usermod -aG sudo attacker

# Копируем исходный код и скрипт атаки
WORKDIR /app
COPY privileged_app.c .
COPY attack.sh .

# Даем права на выполнение
RUN chmod +x attack.sh

# Указываем пользователя (не root)
USER attacker

# Запускаем скрипт при старте
CMD ["/app/attack.sh"]
