ARG ARCH
FROM ${ARCH}python:3.11-alpine
ARG ARCH
ENV FLASK_CONFIG="production" \
    FLASK_APP="kubedash"

WORKDIR /code

RUN apk upgrade --available && sync

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./kubedash /code/kubedash

WORKDIR /code/kubedash

RUN addgroup -S -g 10001 kubedash && \
    adduser -S -u 10001 kubedash -G kubedash && \
    mkdir /tmp/kubedash && \
    chown -R kubedash:kubedash /tmp/kubedash && \
    chown -R kubedash:kubedash /code/kubedash

USER 10001:10001

CMD ["gunicorn", "--conf", "gunicorn_conf.py", "kubedash:app"]
