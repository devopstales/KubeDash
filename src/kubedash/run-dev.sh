#!/bin/bash
USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

# App
#export K8S_CLUSTER_NAME=
export KUBEDASH_VERSION="4.1"
export FLASK_APP="kubedash"
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1
export FLASK_ENV=development
export PYTHONFAULTHANDLER=1
export JAEGER_HTTP_ENDPOINT="http://127.0.0.1:4318/v1/traces"

mkdir -p /tmp/kubedash

# Start DB migration
echo ""
echo "Start Migration"
flask db upgrade
echo "###################################################################################"

# Start Gunicorn (Flask app)
echo ""
echo "Start Applications: KubeDash ${KUBEDASH_VERSION}"
echo "###################################################################################"
#flask run --host=0.0.0.0 --port=8000
gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app --reload