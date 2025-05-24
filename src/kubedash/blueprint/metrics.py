from flask import Blueprint
from prometheus_client import generate_latest

from lib.helper_functions import get_logger

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
