#!/bin/bash

# Fix getpwuid(): uid not found: 1001 by setting the USER env var to prevent python from looking for a matching uid/gid in the password database.
# See https://github.com/python/cpython/blob/v3.6.0/Lib/getpass.py#L155-L170.
USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

echo ""
echo "Start Migration"
echo "###########################################################################################"
flask db upgrade
echo ${KUBEDASH_VERSION} > /code/kubedash/app-release

echo ""
echo "Start Applications"
echo "###########################################################################################"
#flask run --host=0.0.0.0 --port=8000
#python3 kubedash.py
gunicorn --worker-class eventlet --conf gunicorn_conf.py wsgi:app
