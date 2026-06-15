FROM python:3.9-slim

RUN apt-get update && apt-get install -y git && \
    pip install --no-cache-dir pycryptodome pyasn1 psutil
    
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/attack.sh"]
