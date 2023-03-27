#!/bin/bash

export FLASK_APP=kubedash
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1

flask db upgrade

flask run --host 0.0.0.0 --port 8000
