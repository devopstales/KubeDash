#!/bin/bash

eval $(poetry env activate)

export FLASK_APP="kubespace"
export POD_NAMESPACE="balazs-paldi"
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1
#export FLASK_ENV=development
#export PYTHONFAULTHANDLER=1


python3 -m kubespace
