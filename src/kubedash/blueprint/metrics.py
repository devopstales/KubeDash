from flask import Blueprint

from lib.helper_functions import get_logger

from prometheus_client import generate_latest

##############################################################
## Helpers
##############################################################

metrics = Blueprint("metrics", __name__)
logger = get_logger()

##############################################################
## Promatehus Endpoint
##############################################################

@metrics.route('/metrics')
def metric_list():
    return generate_latest()
