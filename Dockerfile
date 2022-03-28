FROM python:3.10.4-buster

WORKDIR /app
COPY ./ ./

RUN python setup.py install

ENTRYPOINT ["fiberfox"]
