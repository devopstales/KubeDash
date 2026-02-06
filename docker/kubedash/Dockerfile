# syntax = docker/dockerfile:1.2
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM python:3.12-alpine AS builder

WORKDIR /code
COPY requirements.txt  /code/
RUN apk add --no-cache postgresql-libs && \
    apk add --no-cache bash gcc musl-dev linux-headers && \
    apk add --no-cache --virtual .build-deps gcc build-base freetype-dev libpng-dev openblas-dev libffi-dev musl-dev postgresql-dev
RUN apk -U upgrade
RUN pip install --no-cache-dir --prefix=/install-dir -r /code/requirements.txt &&\
    pip install --no-cache-dir --prefix=/install-dir -U "pip>=25.3" "setuptools>=78.1.1" "wheel>=0.46.2" 

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
    mkdir -p /code && \
    mkdir -p /code/certs && \
    mkdir -p /code/kubedash/certs && \
    mkdir /tmp/kubedash && \
    chown -R kubedash:kubedash /code && \
    chown -R kubedash:kubedash /tmp/kubedash

COPY entrypoint.sh /entrypoint.sh

RUN apk add --no-cache bash
RUN apk -U upgrade

COPY --from=builder /install-dir /usr/local
ENV PATH=/usr/local/bin:$PATH

COPY --chown=kubedash:kubedash ./kubedash /code/kubedash

# Ensure /code and all subdirectories are owned by kubedash after COPY
RUN chown -R kubedash:kubedash /code

RUN touch /code/kubedash/CA.crt && chown kubedash:kubedash /code/kubedash/CA.crt
RUN touch /code/kubedash/app-release && chown kubedash:kubedash /code/kubedash/app-release

USER 10001:10001

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
