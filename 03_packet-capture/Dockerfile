FROM ubuntu:latest

RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*

COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/attack.sh"]
