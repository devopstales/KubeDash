from flask import Blueprint

from lib_functions.helper_functions import get_logger

from prometheus_client import generate_latest

##############################################################
## Helpers
##############################################################

metrics = Blueprint("metrics", __name__)
logger = get_logger(__name__.split(".")[1])

##############################################################
## Promatehus Endpoint
##############################################################

@metrics.route('/metrics')
def metric_list():
    return generate_latest()