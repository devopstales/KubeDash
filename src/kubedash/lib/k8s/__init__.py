#!/usr/bin/env python3

from opentelemetry import trace

from lib.helper_functions import get_logger

##############################################################
## Helper Functions
##############################################################

logger = get_logger()

tracer = trace.get_tracer(__name__)
