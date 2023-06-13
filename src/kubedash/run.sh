#!/bin/bash

#export FLASK_APP=kubedash
#export FLASK_DEBUG=1
#export TEMPLATES_AUTO_RELOAD=1
#export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

export FLASK_CONFIG="production"
export FLASK_APP="kubedash"

USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

echo "Start Migration"
flask db upgrade

echo "Start Gunicorn"
gunicorn --conf gunicorn_conf.py kubedash:app
