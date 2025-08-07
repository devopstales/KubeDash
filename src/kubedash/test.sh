#!/usr/bin/env bash


poetry install --with test
poetry run pytest --cov=kubedash --cov=blueprint --cov=lib --cov=plugins tests/

#FLASK_APP=kubedash
#
#playwright install
#
#pytest
