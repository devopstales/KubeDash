import json
import logging
import re
import sys
from decimal import Decimal, InvalidOperation
from logging import Logger

import six
import yaml
from flask import flash
from opentelemetry import trace

##############################################################
## Helpers
##############################################################

tracer = trace.get_tracer(__name__)

##############################################################
## Helper Functions
##############################################################

@tracer.start_as_current_span("get_logger")
def get_logger() -> Logger:
    """Generate a Logger for the given module name

    Returns:
        logger (Logger): A Logger for the given module name.
    """
    span = trace.get_current_span()

    # base config
    logging.basicConfig(
            level="INFO",
            format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'
        )
    logging.captureWarnings(True)

    # get logger instance
    logger = logging.getLogger()

    if sys.argv[1] == 'cli' or sys.argv[1] == 'db':
        log = logging.getLogger('werkzeug')
        log.disabled = True

        formatter = logging.Formatter('[%(asctime)s] [{}] [%(levelname)s] %(message)s'.format(sys.argv[1]))
        logger.handlers[0].setFormatter(formatter)

        if tracer and span.is_recording():
            span.set_attribute("run.mode", sys.argv[1])
    else:
        formatter =logging.Formatter('[%(asctime)s] [kubedash] [%(levelname)s] %(message)s')
        logger.handlers[0].setFormatter(formatter)

        if tracer and span.is_recording():
            span.set_attribute("run.mode", "server")

    return logger

##############################################################
## Test Functions
##############################################################

def bool_var_test(var) -> bool:
    """Check if a variable is a valid boolean value
    
    Args:
        var (any): The variable to check.
    
    Returns:
        bool: True if the variable is a valid boolean value, False otherwise.
    """
    if isinstance(var, bool):
        resp = var
    elif isinstance(var, six.string_types):
        if var.lower() in ['true']:
            resp = True
        else:
            resp = False
    else:
        resp = False
    return resp

def email_check(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False

##############################################################
## Formatting Functions
##############################################################

def string2list(string: str) -> list:
    """Function to converst string to list
    
    Args:
        string (str): The string to be converted

    Returns:
        list (list): The list of elements in the string.
    """
    list = string.split()
    return list

def json2yaml(json_input: json) -> yaml:
    """Function to convert JSON to YAML
    
    Args:
        json_input (dict): The JSON data to be converted

    Returns:
        yaml_formatted_data (str): The YAML formatted data.
    """
    json_values = json.dumps(json_input)
    yaml_data = yaml.safe_load(json_values)
    yaml_formatted_data = yaml.dump(yaml_data)
    return yaml_formatted_data

def format_json(json_input: json) -> str:
    """Function to format JSON to a human-readable string
    
    Args:
        json_input (dict): The JSON data to be formatted

    Returns:
        josn_formatted_data (str): The formatted JSON data.
    """
    josn_formatted_data = json.dumps(json_input, indent=2)
    return josn_formatted_data

def find_values_in_json(id: int, json_repr) -> list:
    """Find values in JSON
    
    Args:
        id (int): The ID to search for in the JSON.
        json_repr (str): The JSON data as a string.

    Returns:
        list: A list of values found in the JSON with the given ID.
    """
    results = list()

    def _decode_dict(a_dict):
        try:
            results.append(a_dict[id])
        except KeyError:
            pass
        return a_dict

    json.loads(json_repr, object_hook=_decode_dict) # Return value ignored.
    return results

def trimAnnotations(annotations: dict) -> dict:
    """Trim annotations
    
    Args:
        annotations (dict): The annotations to be trimmed.

    Returns:
        dict: The trimmed annotations.
    """
    trimmed_annotations = {}
    for key, value in annotations.items():
        if key == 'kubectl.kubernetes.io/last-applied-configuration':
            continue
        elif key == "autoscaling.alpha.kubernetes.io/conditions":
            continue
        else:
            trimmed_annotations[key] = value
    return trimmed_annotations

##############################################################
## Percentage Functions
##############################################################

def parse_quantity(quantity: str):
    """
    Parse kubernetes canonical form quantity like 200Mi to a decimal number.
    Supported SI suffixes:
    base1024: Ki | Mi | Gi | Ti | Pi | Ei
    base1000: n | u | m | "" | k | M | G | T | P | E
    See https://github.com/kubernetes/apimachinery/blob/master/pkg/api/resource/quantity.go

    Args:
        quantity: string. kubernetes canonical form quantity
    
    Returns:
        Decimal
    
    Raises:
        ValueError on invalid or unknown input
    """
    if isinstance(quantity, (int, float, Decimal)):
        return Decimal(quantity)

    exponents = {"n": -3, "u": -2, "m": -1, "K": 1, "k": 1, "M": 2,
                 "G": 3, "T": 4, "P": 5, "E": 6}

    quantity = str(quantity)
    number = quantity
    suffix = None
    if len(quantity) >= 2 and quantity[-1] == "i":
        if quantity[-2] in exponents:
            number = quantity[:-2]
            suffix = quantity[-2:]
    elif len(quantity) >= 1 and quantity[-1] in exponents:
        number = quantity[:-1]
        suffix = quantity[-1:]

    try:
        number = Decimal(number)
    except InvalidOperation:
        raise ValueError("Invalid number format: {}".format(number))

    if suffix is None:
        return number

    if suffix.endswith("i"):
        base = 1024
    elif len(suffix) == 1:
        base = 1000
    else:
        raise ValueError("{} has unknown suffix".format(quantity))

    # handle SI inconsistency
    if suffix == "ki":
        raise ValueError("{} has unknown suffix".format(quantity))

    if suffix[0] not in exponents:
        raise ValueError("{} has unknown suffix".format(quantity))

    exponent = Decimal(exponents[suffix[0]])
    return number * (base ** exponent)

def calcPercent(x, y, integer = False):
    """Calculate the percentage.
    """
    percent = x / y * 100
   
    if integer:
        return int(percent)
    return percent

##############################################################
## Error Handler Functions
##############################################################

def ErrorHandler(logger, error, action):
    """Handle errors and flash messages
    
    Args:
        logger (Logger): The Logger for the module.
        error (str): The error to handle.
        action (str): The action being performed.
    """
    if hasattr(error, '__iter__'):
        if 'status' in error:
            if error.status == 401:
                flash("401 - Unauthorized: User cannot connect to Kubernetes", "danger")
                logger.error("401 - Unauthorized: User cannot connect to Kubernetes")
            elif error.status == 403:
                flash("403 - Forbidden: User cannot %s" % action, "danger")
                logger.error("403 - Forbidden: User cannot %s" % action)
        else:
            flash("Exception: %s" % action, "danger")
            logger.error("Exception: %s %s \n" % (action, error))
    else:
        flash("Exception: %s" % action, "danger")
        logger.error("Exception: %s %s \n" % (action, error))

def NoFlashErrorHandler(logger, error, action):
    """Handle errors without flash messages
    
    Args:
        logger (Logger): The Logger for the module.
        error (str): The error to handle.
        action (str): The action being performed.
    """
    if hasattr(error, '__iter__'):
        if 'status' in error:
            if error.status == 401:
                logger.error("401 - Unauthorized: User cannot connect to Kubernetes")
            elif error.status == 403:
                logger.error("403 - Forbidden: User cannot %s" % action)
        else:
            logger.error("Exception: %s \n" % action)
    else:
        logger.error("Exception: %s" % action)

def ResponseHandler(message, status):
    """Flash a message
    
    Args:
        message (str): The message to be displayed
        status (str): The status of the message (e.g., "success", "danger", etc.)
    """
    flash(message, status)
