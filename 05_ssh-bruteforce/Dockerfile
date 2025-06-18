FROM debian:latest

RUN apt-get update && apt-get install -y sshpass openssh-client && rm -rf /var/lib/apt/lists/*

COPY creds.txt /tmp/creds.txt
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/attack.sh"]
