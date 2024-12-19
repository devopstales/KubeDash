FROM python:3.11-alpine3.20

RUN apk add --no-cache postgresql-libs && \
    apk add --no-cache bash gcc musl-dev linux-headers && \
    apk add --no-cache --virtual .build-deps gcc build-base freetype-dev libpng-dev openblas-dev libffi-dev musl-dev postgresql-dev
RUN apk -U upgrade

COPY requirements.txt /tmp/requirements.txt
COPY tests/requirements.txt /tmp/requirements2.txt

RUN mkdir /tmp/kubedash
RUN pip install --no-cache-dir -r /tmp/requirements.txt
#RUN pip install --no-cache-dir -r /tmp/requirements2.txt

ENV KUBEDASH_VERSION="3.1"
ENV FLASK_APP="kubedash"
ENV FLASK_DEBUG=1
ENV TEMPLATES_AUTO_RELOAD=1