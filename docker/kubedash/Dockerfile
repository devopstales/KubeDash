# syntax = docker/dockerfile:1.2
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM python:3.11-alpine3.20 AS builder

WORKDIR /code
COPY requirements.txt  /code/
RUN apk add --no-cache postgresql-libs && \
    apk add --no-cache bash gcc musl-dev linux-headers && \
    apk add --no-cache --virtual .build-deps gcc build-base freetype-dev libpng-dev openblas-dev libffi-dev musl-dev postgresql-dev
RUN apk -U upgrade
RUN pip install --no-cache-dir --target=/app/requirements -r /code/requirements.txt

# main Contaiber
ARG BUILDPLATFORM=linux/amd64
ARG VERSION
ARG BUILD_DATE
FROM --platform=$BUILDPLATFORM python:3.11-alpine3.20
ARG BUILDPLATFORM=linux/amd64
ARG VERSION
ARG BUILD_DATE

ENV FLASK_CONFIG="production" \
    FLASK_APP="kubedash" \
    KUBEDASH_VERSION=${VERSION}

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

WORKDIR /code/kubedash

RUN addgroup -S -g 10001 kubedash && \
    adduser -S -u 10001 kubedash -G kubedash && \
    mkdir /tmp/kubedash && \
    chown -R kubedash:kubedash /tmp/kubedash

COPY entrypoint.sh /entrypoint.sh

RUN apk add --no-cache bash py3-setuptools
RUN apk -U upgrade

COPY --from=builder /app/requirements /usr/local/lib/python3.11/site-packages
COPY --chown=kubedash:kubedash ./kubedash /code/kubedash

RUN touch /code/kubedash/CA.crt && chown kubedash:kubedash /code/kubedash/CA.crt

USER 10001:10001

EXPOSE 8000
ENV PATH=/usr/local/lib/python3.11/site-packages/bin:$PATH
ENTRYPOINT ["/entrypoint.sh"]
