#!/usr/bin/env bash


poetry install --with test
poetry run pytest --cov=kubedash tests/

#FLASK_APP=kubedash
#
#playwright install
#
#pytest
