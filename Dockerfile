FROM ubuntu as APP

RUN mkdir /app 
WORKDIR /app

ADD dodas-x509 /usr/local/bin/dodas-x509

ENTRYPOINT ["dodas-x509"]