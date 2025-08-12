#!/bin/bash

USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

export DOCKER_COMPOSE_FILES="-f ../../deploy/docker-compose/dc-nginx.yaml"

# App
#export FLASK_APP="kubedash"
#export FLASK_DEBUG=1
#export TEMPLATES_AUTO_RELOAD=1
#export FLASK_ENV=development
#export PYTHONFAULTHANDLER=1
export POD_NAMESPACE="balazs-paldi"

mkdir -p /tmp/kubedash

$(poetry env activate)

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
task docker-up

# Start DB migration
echo ""
echo "Start Migration"
flask db upgrade
echo "###########################################################################################"

# Start Gunicorn (Flask app)
echo ""
echo "Start Application"
echo "###########################################################################################"
gunicorn --worker-class gevent --conf gunicorn_conf.py wsgi:app --reload --preload
