#!/bin/bash

export FLASK_APP=kubedash.py
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1

flask run --host 0.0.0.0