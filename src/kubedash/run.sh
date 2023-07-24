#!/bin/bash

export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1
#export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#export FLASK_CONFIG="production" # redirect to https
export FLASK_APP="kubedash"

USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

echo "Start Migration"
flask db upgrade

mkdir -p /tmp/kubedash

echo "Start Application"
#flask run --host=127.0.0.1 --port=8000
#gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app
python3 kubedash.py
