FROM golang:1.20-alpine

RUN apk add --no-cache git

COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/attack.sh"]
