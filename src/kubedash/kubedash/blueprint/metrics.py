from flask import Blueprint, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from kubedash.lib.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

metrics_bp = Blueprint("metrics", __name__)
logger = get_logger()

##############################################################
## Promatehus Endpoint
##############################################################

@metrics_bp.route('/metrics')
def metric_list():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
