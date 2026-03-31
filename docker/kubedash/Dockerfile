# syntax = docker/dockerfile:1.2
# ========== Stage 1: Base Image ==========
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM public.ecr.aws/amazonlinux/amazonlinux:2023 AS base

# dist upgrade all packages to the latest version
RUN dnf clean all && dnf update -y --releasever=latest

ENV PYTHON_VERSION=3.12

RUN --mount=type=cache,target=/var/cache/dnf \
    dnf makecache && \
    dnf -y update && \
    dnf install -y python${PYTHON_VERSION} python${PYTHON_VERSION}-pip shadow-utils && \
    update-alternatives --install /usr/bin/python python /usr/bin/python${PYTHON_VERSION} 20 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip-${PYTHON_VERSION} 20 && \
    update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip-${PYTHON_VERSION} 20 && \
    update-alternatives --set python /usr/bin/python${PYTHON_VERSION} && \
    dnf -y update && \
    dnf clean all

# ========== Stage 2: Build Image ==========
FROM base AS builder

WORKDIR /code
COPY requirements.txt  /code/

# Install system dependencies and ensure all packages are up to date
RUN dnf makecache && \
    dnf -y update && \
    dnf install -y \
    postgresql-libs \
    gcc \
    python3-devel \
    postgresql-devel \
    freetype-devel \
    libpng-devel \
    openblas-devel \
    libffi-devel \
    make \
    && dnf -y update && \
    dnf clean all

RUN pip install --no-cache-dir --prefix=/install-dir -U "pip>=26.0" "setuptools>=78.1.1" "wheel>=0.46.2" && \
    /install-dir/bin/pip install --no-cache-dir --prefix=/install-dir -r requirements.txt

# ========== Stage 3: Runtime Image ==========
FROM base AS runtime
ARG VERSION
ARG BUILD_DATE

ENV FLASK_CONFIG="production" \
    FLASK_APP="kubedash" \
    KUBEDASH_VERSION=${VERSION} \
    PYTHONPATH=/usr/local/lib64/python3.12/site-packages:/usr/local/lib/python3.12/site-packages

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

# Copy virtual environment from builder
COPY --from=builder /install-dir /usr/local
ENV PATH=/usr/local/bin:$PATH

# Update the system to ensure all security patches are applied
# This updates all packages including: libcap, libtasn1, libxml2, openssl, python3-pip packages
RUN --mount=type=cache,target=/var/cache/dnf \
    dnf makecache && \
    dnf -y update && \
    dnf clean all

# Runtime configuration
RUN useradd -u 10001 -d /code/kubedash kubedash && \
    mkdir -p /code && \
    mkdir -p /code/certs && \
    mkdir -p /code/kubedash/certs && \
    mkdir /tmp/kubedash && \
    chown -R kubedash:kubedash /code && \
    chown -R kubedash:kubedash /tmp/kubedash && \
    touch /code/kubedash/CA.crt && \
    chown kubedash:kubedash /code/kubedash/CA.crt && \
    touch /code/kubedash/app-release && \
    chown kubedash:kubedash /code/kubedash/app-release
    
COPY --chown=kubedash:kubedash ./kubedash /code/kubedash

# Ensure /code and all subdirectories are owned by kubedash after COPY
RUN chown -R kubedash:kubedash /code

COPY entrypoint.sh /entrypoint.sh
USER kubedash
EXPOSE 8000
CMD ["/entrypoint.sh"]
