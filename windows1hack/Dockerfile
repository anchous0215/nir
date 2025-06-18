FROM debian:latest

RUN apt-get update && apt-get install -y sudo bash

COPY script.sh /usr/local/bin/script.sh

RUN chmod +x /usr/local/bin/script.sh

ENTRYPOINT ["/usr/local/bin/script.sh"]
