#!/bin/bash

# App
#export K8S_CLUSTER_NAME=
export KUBEDASH_VERSION="3.1"
export FLASK_APP="kubedash"
export FLASK_DEBUG=1
export TEMPLATES_AUTO_RELOAD=1

#export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
#export OTEL_EXPORTER_OTLP_INSECURE=true
#export OTEL_TRACES_EXPORTER=otlp_proto_http

#export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318

export OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED=true

export OTEL_RESOURCE_ATTRIBUTES="service.name=kubedash"
export OTEL_SERVICE_NAME="kubedash"
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
export OTEL_METRICS_EXPORTER=""

opentelemetry-instrument \
	--traces_exporter console,otlp \
	--metrics_exporter console \
	flask run --host=0.0.0.0 --port=8000
