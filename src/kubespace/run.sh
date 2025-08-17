#!/bin/bash

eval $(poetry env activate)

export FLASK_APP="kubespace"
export POD_NAMESPACE="balazs-paldi"


python3 -m kubespace
