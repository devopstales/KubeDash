ARG ARCH
FROM ${ARCH}python:3.11-alpine
ARG ARCH
ENV FLASK_CONFIG="production" \
    FLASK_APP="kubedash"

WORKDIR /code

RUN apk -U upgrade && \
    apk add --no-cache bash gcc musl-dev linux-headers

COPY requirements.txt  /code/
COPY entrypoint.sh /entrypoint.sh

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./kubedash /code/kubedash

WORKDIR /code/kubedash

RUN addgroup -S -g 10001 kubedash && \
    adduser -S -u 10001 kubedash -G kubedash && \
    mkdir /tmp/kubedash && \
    chown -R kubedash:kubedash /tmp/kubedash && \
    chown -R kubedash:kubedash /code/kubedash

USER 10001:10001

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
