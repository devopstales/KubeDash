#!/bin/bash
USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

# App
#export K8S_CLUSTER_NAME=
export KUBEDASH_VERSION="3.1"
export FLASK_APP="kubedash"
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1


mkdir -p /tmp/kubedash

# Nginx Reverse Proxy
#kubectx $K8S_CLUSTER_NAME
CA_CERTS_FOLDER="$PWD/../../deploy/docker-compose/config"
# Generate Certificate
if [ ! -f $CA_CERTS_FOLDER/rootCA.pem ]; then
    echo "##  Generate CA Certificate"
    CAROOT=${CA_CERTS_FOLDER} mkcert -install kubedash.k3s.intra
    rm -rf $CA_CERTS_FOLDER/kubedash.k3s.*/
    mv kubedash.k3s.intra.pem kubedash.k3s.intra-key.pem $CA_CERTS_FOLDER/
fi

echo "Start Nginx Proxy in Docker Compose"
docker compose -f ../../deploy/docker-compose/dc-nginx.yaml down
docker compose -f ../../deploy/docker-compose/dc-nginx.yaml up -d

echo ""
echo "Start Migration"
echo ""
flask db upgrade

echo ""
echo "Start Applications: KubeDash ${KUBEDASH_VERSION}"
echo ""
#flask run --host=0.0.0.0 --port=8000
gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app
#opentelemetry-instrument gunicorn --worker-class eventlet --conf gunicorn_conf.py kubedash:app

#trap ctrl_c INT
#function ctrl_c() {
#    docker-compose -f ../../deploy/docker-compose/dc-nginx.yaml stop
#    exit 0
#}
