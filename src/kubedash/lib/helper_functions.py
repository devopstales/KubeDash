import json
import logging
import re
import sys
import colorlog
from colorlog.escape_codes import escape_codes
from decimal import Decimal, InvalidOperation
from logging import Logger

import six
import yaml
from flask import flash, has_request_context
from opentelemetry import trace

##############################################################
## Helpers
##############################################################

tracer = trace.get_tracer(__name__)

##############################################################
## Helper Functions
##############################################################
import threading

class ThreadedTicker:
    def __init__(self, interval_sec, func, *args, **kwargs):
        """
        :param interval_sec: How often to run the function (in seconds)
        :param func: The function to call repeatedly
        :param args: Positional arguments for the function
        :param kwargs: Keyword arguments for the function
        """
        self.interval = interval_sec
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

        # Setup logger for ThreadedTicker
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        # Create console handler (optional: add file handler too)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        # Create formatter and add to handler
        formatter = logging.Formatter(
            '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'
        )
        ch.setFormatter(formatter)

        # Add handler to logger (if not already added)
        if not self.logger.hasHandlers():
            self.logger.addHandler(ch)

    def start(self):
        """Start the ticker in a separate thread."""
        self.logger.info("Starting ticker...")
        self._thread.start()

    def stop(self):
        """Stop the ticker loop."""
        self.logger.info("Stopping ticker...")
        self._stop_event.set()
        self._thread.join()

    def _run(self):
        """Run the function repeatedly at the given interval."""
        self.logger.debug("Ticker loop has started.")
        while not self._stop_event.is_set():
            try:
                self.logger.debug("Executing scheduled function.")
                self.func(*self.args, **self.kwargs)
            except Exception:
                # Log exception with traceback
                self.logger.exception("An error occurred while executing the function:")
            # Wait until the next tick or until stopped
            if not self._stop_event.wait(self.interval):
                continue
        self.logger.debug("Ticker loop has exited.")

@tracer.start_as_current_span("get_logger")
def get_logger() -> Logger:
    """Generate a Logger for the given module name

    Returns:
        logger (Logger): A Logger for the given module name.
    """
    span = trace.get_current_span()

    # Remove existing handlers (avoid duplicate logs if reconfigured)
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Define color codes
    BLACK = escape_codes['black']  # black color code
    PURPLE = escape_codes['purple']  # purple color code
    RESET = escape_codes['reset']  # reset code
    GREEN = '\033[32m'  # ANSI green
    RED = '\033[31m'    # ANSI red

    class BooleanColorFormatter(colorlog.ColoredFormatter):
        def format(self, record):
            msg = super().format(record)
            # Colorize True and False words
            msg = msg.replace("True", f"{GREEN}True{RESET}")
            msg = msg.replace("False", f"{RED}False{RESET}")
            return msg

    # Define colorlog formatter with custom colors + BooleanColorFormatter
    formatter = BooleanColorFormatter(
        fmt=f'[{BLACK}%(asctime)s{RESET}] [{PURPLE}%(name)s{RESET}] [%(log_color)s%(levelname)s%(reset)s] %(message)s',
        log_colors={
            'DEBUG': 'bold_black',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    )

    # Set up stream handler with color
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False  # Prevent double logs

    # Disable noisy loggers in CLI/DB mode
    if sys.argv[1] in ('cli', 'db'):
        log = logging.getLogger('werkzeug')
        log.disabled = True
        logger.name = sys.argv[1]

        if tracer and span.is_recording():
            span.set_attribute("run.mode", sys.argv[1])
    else:
        logger.name = "kubedash"
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
    if annotations is not None:
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
                if has_request_context():
                    flash("401 - Unauthorized: User cannot connect to Kubernetes", "danger")
                logger.error("401 - Unauthorized: User cannot connect to Kubernetes")
            elif error.status == 403:
                if has_request_context():
                    flash("403 - Forbidden: User cannot %s" % action, "danger")
                logger.error("403 - Forbidden: User cannot %s" % action)
        else:
            if has_request_context():
                flash("Exception: %s" % action, "danger")
            logger.error("Exception: %s %s \n" % (action, error))
    else:
        if has_request_context():
            flash("Exception: %s" % action, "danger")
        logger.error("Exception: %s %s \n" % (action, error))

def ResponseHandler(message, status):
    """Flash a message
    
    Args:
        message (str): The message to be displayed
        status (str): The status of the message (e.g., "success", "danger", etc.)
    """
    flash(message, status)
