# Используем базовый образ ubuntu
FROM ubuntu:latest

# Установка необходимых пакетов
RUN apt-get update && \ 
    apt-get install -y sudo bash && \ 
    apt-get clean

# Создаем нового пользователя и задаем пароль
RUN useradd -m -s /bin/bash user && \ 
    echo "user:password123" | chpasswd && \
    usermod -aG sudo user

# Копируем скрипт в контейнер
COPY script.sh /usr/local/bin/script.sh

# Даем права на выполнение скрипта
RUN chmod +x /usr/local/bin/script.sh

# Указываем, что контейнер должен запускаться от имени нового пользователя
USER user

# Запускаем скрипт при старте контейнера
CMD ["/usr/local/bin/script.sh"]

