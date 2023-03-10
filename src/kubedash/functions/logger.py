#!/usr/bin/env python3

import os, logging

LOGLEVEL = os.environ.get('LOGGING_LEVEL', 'INFO').upper()

logging.basicConfig(
    level=LOGLEVEL,
    format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
    )
logger = logging.getLogger('KubeDash')

if LOGLEVEL == "DEBUG":
    logging.captureWarnings(True)