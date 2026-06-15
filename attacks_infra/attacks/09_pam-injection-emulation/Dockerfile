FROM debian:latest

RUN apt-get update && apt-get install -y sudo sed && rm -rf /var/lib/apt/lists/*

# Создаем фейковую конфигурацию PAM для безопасной эмуляции
RUN mkdir -p /tmp/test_pam.d && \
    echo "auth required pam_unix.so" > /tmp/test_pam.d/common-auth && \
    echo "account required pam_unix.so" >> /tmp/test_pam.d/common-auth
    
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/attack.sh"]
