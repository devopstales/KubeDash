#!/bin/bash

#export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1
#export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#export FLASK_CONFIG="production" # redirect to https
export FLASK_APP="kubedash"

export OIDC_ISSUER_URL="https://sso.shiwaforce.com/auth/realms/shiwaforce"
export OIDC_CLIENT_ID="cl03-dashboard-proxy"
export OIDC_SECRET="df4c4725-98c9-4e92-bcb1-3c761d5adc3f"
export OIDC_SCOPE="groups email openid profile good-service"
# "openid email profile"
export OIDC_CALLBACK_URL="http://127.0.0.1:8000"

USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

echo "Start Migration"
flask db upgrade

mkdir -p /tmp/kubedash

echo "Start Gunicorn"
python3 kubedash.py
#flask run --host=127.0.0.1 --port=8000
#gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app
#waitress-serve --host 127.0.0.1 --port 8000 kubedash:app

#uwsgi --socket 127.0.0.1:8000 -p 1 --protocol=http --http-websockets -w kubedash:app
#uwsgi --http 127.0.0.1:8000 -p 1 --gevent 100 -w kubedash:app
#uwsgi -p 1 --http 127.0.0.1:8000 --gevent 1000 --http-websockets --wsgi-file kubedash.py --callable app
