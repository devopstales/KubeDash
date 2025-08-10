#!/usr/bin/env python3

from opentelemetry import trace

from kubedash.lib.helper_functions import get_logger

##############################################################
## Helper Functions
##############################################################

logger = get_logger()

from kubedash.lib.opentelemetry import get_tracer
from opentelemetry import trace
tracer = get_tracer()
