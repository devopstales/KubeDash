#!/bin/bash

export FLASK_APP=kubedash
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1
#export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

flask db upgrade

flask run --host 0.0.0.0 --port 8800
