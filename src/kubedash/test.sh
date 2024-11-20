#!/usr/bin/env bash

FLASK_APP=kubedash

playwright install

pytest
