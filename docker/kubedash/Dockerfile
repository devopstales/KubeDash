ARG ARCH
ARG VERSION
ARG BUILD_DATE
FROM ${ARCH}python:3.11-alpine
ARG ARCH
ARG VERSION
ARG BUILD_DATE

ENV FLASK_CONFIG="production" \
    FLASK_APP="kubedash"

# https://github.com/opencontainers/image-spec/blob/main/annotations.md#back-compatibility-with-label-schema
LABEL org.opencontainers.image.vendor="devopstales" \
      org.opencontainers.image.authors="devopstales" \
      org.opencontainers.imeg.url="https://devopstales.github.io" \
      org.opencontainers.image.licenses="Apache 2.0" \
      org.opencontainers.image.title="kubedash" \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.description="General-purpose web UI for Kubernetes clusters" \
      org.opencontainers.image.source="https://github.com/devopstales/kubedash" \
      org.opencontainers.image.documentation="https://devopstales.github.io/kubedash" \
      org.opencontainers.image.created=${BUILD_DATE}

WORKDIR /code

RUN apk -U upgrade && \
    apk add --no-cache bash gcc musl-dev linux-headers

COPY requirements.txt  /code/
COPY entrypoint.sh /entrypoint.sh

RUN apk --update add gcc build-base freetype-dev libpng-dev openblas-dev libffi-dev && \
    pip install --no-cache-dir --upgrade -r /code/requirements.txt && \
    apk del gcc build-base freetype-dev libpng-dev openblas-dev libffi-dev

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
