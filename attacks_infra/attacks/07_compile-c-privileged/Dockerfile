FROM gcc:latest

# Устанавливаем sudo и создаем пользователя с правами
RUN apt-get update && apt-get install -y sudo && \
    useradd -m -s /bin/bash attacker && \
    echo "attacker:attackerpass" | chpasswd && \
    usermod -aG sudo attacker

WORKDIR /app
COPY privileged_app.c .
COPY attack.sh .
RUN chmod +x attack.sh

# Запускаем от имени непривилегированного пользователя
USER attacker
CMD ["/app/attack.sh"]
