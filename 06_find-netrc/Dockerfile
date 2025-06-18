FROM alpine:latest

# Создаем фейковые файлы для поиска
RUN mkdir -p /home/user1/.config && \
    echo "machine ftp.example.com login user1 password mysecretpass" > /home/user1/.netrc && \
    touch /home/user1/somefile.txt && \
    mkdir -p /var/www && \
    echo "machine api.example.com login api_user password anothersecret" > /var/www/.netrc
    
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/attack.sh"]
