import json
import logging
import os
import re
import sys
from datetime import datetime as dt, timezone
import colorlog
import validators
from colorlog.escape_codes import escape_codes
from decimal import Decimal, InvalidOperation
from logging import Logger
from urllib.parse import urlparse, urljoin

import six
import yaml
from flask import g, flash, has_request_context, Request
from typing import Optional, Union, Tuple

##############################################################
## Helpers
##############################################################

from lib.opentelemetry import get_tracer
from opentelemetry import trace
tracer = get_tracer()

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

        # Canonical format (same as get_logger): [timestamp] [no-id] [logger] [LEVEL] message
        class CanonicalFormatter(logging.Formatter):
            def formatTime(self, record, datefmt=None):
                ct = dt.fromtimestamp(record.created)
                s = ct.strftime("%Y-%m-%d %H:%M:%S")
                return "%s,%03d" % (s, record.msecs)

        formatter = CanonicalFormatter(
            '[%(asctime)s] [no-id] [%(name)s] [%(levelname)s] %(message)s'
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


# Cached logging config from kubedash.ini so we don't re-read on every get_logger() call
_log_config_cache = None


def _get_logging_config(ini_config=None):
    """Read [logging] from kubedash.ini or from provided ConfigParser. Returns dict with 'format' and 'level'."""
    global _log_config_cache
    if ini_config is not None and ini_config.has_section('logging'):
        format_val = ini_config.get('logging', 'format', fallback='text').strip().lower()
        if format_val not in ('text', 'json'):
            format_val = 'text'
        level_val = ini_config.get('logging', 'level', fallback='INFO').strip().upper()
        return {'format': format_val, 'level': level_val}
    if _log_config_cache is not None:
        return _log_config_cache
    import configparser
    config = configparser.ConfigParser()
    ini_path = os.environ.get('KUBEDASH_INI_PATH', 'kubedash.ini')
    if os.path.isfile(ini_path):
        config.read(ini_path)
    format_val = 'text'
    level_val = 'INFO'
    if config.has_section('logging'):
        format_val = config.get('logging', 'format', fallback='text').strip().lower()
        if format_val not in ('text', 'json'):
            format_val = 'text'
        level_val = config.get('logging', 'level', fallback='INFO').strip().upper()
    _log_config_cache = {'format': format_val, 'level': level_val}
    return _log_config_cache


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line for ELK/Loki. Same trace_id and logger names as text mode."""

    def format(self, record):
        if not hasattr(record, 'correlation_id'):
            record.correlation_id = 'no-id'
        if not record.correlation_id:
            record.correlation_id = 'no-id'
        # ISO timestamp with Z (UTC)
        ct = dt.fromtimestamp(record.created, tz=timezone.utc)
        ts = ct.strftime('%Y-%m-%dT%H:%M:%S') + '.%03dZ' % (record.msecs,)
        obj = {
            'timestamp': ts,
            'trace_id': record.correlation_id,
            'logger': record.name,
            'level': record.levelname,
            'message': record.getMessage(),
        }
        if record.exc_info:
            obj['error_type'] = record.exc_info[0].__name__ if record.exc_info[0] else None
            obj['stack_trace'] = self.formatException(record.exc_info) if record.exc_info else None
        return json.dumps(obj, default=str)


@tracer.start_as_current_span("get_logger")
def get_logger(ini_config=None) -> Logger:
    """Generate a Logger with correlation ID support. Uses [logging] from kubedash.ini or ini_config if provided."""
    span = trace.get_current_span()

    # Remove existing handlers (avoid duplicate logs if reconfigured)
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Define color codes
    BLACK = escape_codes['black']
    PURPLE = escape_codes['purple']
    RESET = escape_codes['reset']
    GREEN = '\033[32m'
    RED = '\033[31m'

    class BooleanColorFormatter(colorlog.ColoredFormatter):
        """Canonical log format: [YYYY-MM-DD HH:MM:SS,mmm] [trace-id] [logger] [LEVEL] message."""

        def formatTime(self, record, datefmt=None):
            """Produce timestamp in canonical form with milliseconds."""
            ct = dt.fromtimestamp(record.created)
            s = ct.strftime("%Y-%m-%d %H:%M:%S")
            return "%s,%03d" % (s, record.msecs)

        def format(self, record):
            # Ensure correlation_id exists on the record
            if not hasattr(record, 'correlation_id'):
                record.correlation_id = 'no-id'
            if not record.correlation_id:
                record.correlation_id = 'no-id'
            msg = super().format(record)
            # Colorize True and False words
            msg = msg.replace("True", f"{GREEN}True{RESET}")
            msg = msg.replace("False", f"{RED}False{RESET}")
            return msg

    # Define colorlog formatter with safe correlation_id fallback
    formatter = BooleanColorFormatter(
        fmt=f'[{BLACK}%(asctime)s{RESET}] [%(correlation_id)s] [{PURPLE}%(name)s{RESET}] '
            f'[%(log_color)s%(levelname)s%(reset)s] %(message)s',
        log_colors={
            'DEBUG': 'bold_black',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    )

    log_config = _get_logging_config(ini_config)
    if log_config['format'] == 'json':
        formatter = JsonFormatter()

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    level_name = log_config.get('level', 'INFO')
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False

    # Add correlation_id filter to ensure it's always available
    class CorrelationIDFilter(logging.Filter):
        def filter(self, record):
            if not hasattr(record, 'correlation_id'):
                corr_id = 'no-id'
                try:
                    from flask import has_app_context, g
                    if has_app_context():
                        corr_id = getattr(g, 'correlation_id', 'no-id')
                    else:
                        current_span = tracer.get_current_span()
                        if current_span.is_recording():
                            ctx = current_span.get_span_context()
                            if ctx.is_valid:
                                corr_id = f"{ctx.trace_id:032x}"
                except Exception:
                    # Intentionally swallow so logging never fails; record keeps no-id
                    pass
                record.correlation_id = corr_id
            return True

    logger.addFilter(CorrelationIDFilter())

    # Disable noisy loggers in CLI/DB mode
    if len(sys.argv) > 1 and sys.argv[1] in ('cli', 'db'):
        logging.getLogger('werkzeug').disabled = True
        logger.name = sys.argv[1]
        if tracer and hasattr(span, 'is_recording') and span.is_recording():
            span.set_attribute("run.mode", sys.argv[1])
    else:
        logger.name = "kubedash"
        if tracer and hasattr(span, 'is_recording') and span.is_recording():
            span.set_attribute("run.mode", "server")

    return logger

def is_safe_url(url_target: Optional[str], url_request: Union[Request, str]) -> bool:
    """
    Check if the target URL is safe to prevent open redirects.
    
    Args:
        url_target: The target URL to validate (can be None)
        url_request: Either a Flask Request object or host URL string
    
    Returns:
        bool: True if URL is safe, False otherwise
    """
    if not url_target:
        return False
    
    # Get reference URL
    if isinstance(url_request, Request):
        ref_url = urlparse(url_request.host_url)
    else:
        ref_url = urlparse(url_request)
    
    # Resolve target URL
    test_url = urlparse(urljoin(ref_url.geturl(), url_target))
    
    # Validate scheme and netloc
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc



def is_valid_url(url):
    """Check if a URL is valid.
    
    Args:
        url (str): The URL to check.
        
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    if url.startswith(('http://', 'https://')):
        return validators.url(url)
    else:
        # If the URL does not start with http:// or https://, we assume it's not valid
        return False

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
    with tracer.start_as_current_span("parse_quantity") as span:
        span.set_attribute("quantity", quantity)
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
    with tracer.start_as_current_span("calcPercent") as span:
        span.set_attribute("x", x)
        span.set_attribute("y", y)
        
        if y == 0:
            return 0 if integer else 0.0
        
        percent = x / y * 100
    
        if integer:
            return int(percent)
        return percent

##############################################################
## Error Handler Functions
##############################################################

def ErrorHandler(logger, error, action):
    """Log and optionally flash errors. Use for API and critical paths so format and level are consistent.
    When error is an Exception, logs with exc_info=True so stack traces appear in logs.

    Args:
        logger: The Logger for the module.
        error: The error (Exception instance, or object with .status for API errors).
        action: Description of the action being performed.
    """
    exc_info = isinstance(error, BaseException)
    if hasattr(error, '__iter__'):
        if hasattr(error, 'status'):
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
                logger.error("Exception: %s %s", action, error, exc_info=exc_info)
        else:
            if has_request_context():
                flash("Exception: %s" % action, "danger")
            logger.error("Exception: %s %s", action, error, exc_info=exc_info)
    else:
        if has_request_context():
            flash("Exception: %s" % action, "danger")
        logger.error("Exception: %s %s", action, error, exc_info=exc_info)
        
def WarningHandler(logger, warning, action):
    """Handle warnings and flash messages
    
    Args:
        logger (Logger): The Logger for the module.
        warning (str): The warning to handle.
        action (str): The action being performed.
    """
    if has_request_context():
        flash(warning, "warning")
    logger.warning("%s %s" % (action, warning))
        
def MessageHandler(logger, message, action):
    """Handle messages and flash them
    
    Args:
        logger (Logger): The Logger for the module.
        message (str): The message to handle.
        action (str): The action being performed.
    """
    if has_request_context():
        flash(message, "success")
    logger.info("%s %s" % (action, message))

def ResponseHandler(message, status):
    """Flash a message
    
    Args:
        message (str): The message to be displayed
        status (str): The status of the message (e.g., "success", "danger", etc.)
    """
    flash(message, status)

##############################################################
## Security Validation Functions
##############################################################

def validate_k8s_resource_name(name: str, resource_type: str = "resource") -> Tuple[bool, Optional[str]]:
    """
    Validate Kubernetes resource name according to RFC 1123 subdomain format.
    
    Kubernetes resource names must:
    - Be lowercase alphanumeric characters or '-'
    - Start and end with an alphanumeric character
    - Be at most 253 characters
    - Not contain '..' or path separators
    
    Args:
        name: The resource name to validate
        resource_type: Type of resource for error messages (e.g., "pod", "namespace")
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not name or not isinstance(name, str):
        return False, f"Invalid {resource_type} name: must be a non-empty string"
    
    # Check for path traversal attempts
    if '..' in name or '/' in name or '\\' in name:
        return False, f"Invalid {resource_type} name: contains path traversal characters"
    
    # Check length
    if len(name) > 253:
        return False, f"Invalid {resource_type} name: exceeds maximum length of 253 characters"
    
    # Kubernetes DNS-1123 subdomain format: [a-z0-9]([-a-z0-9]*[a-z0-9])?
    # Must start and end with alphanumeric, can contain hyphens in between
    if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', name):
        return False, f"Invalid {resource_type} name: must match DNS-1123 subdomain format (lowercase alphanumeric and hyphens)"
    
    return True, None

def validate_namespace(name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate Kubernetes namespace name.
    
    Args:
        name: The namespace name to validate
    
    Returns:
        tuple: (is_valid, error_message)
    """
    return validate_k8s_resource_name(name, "namespace")

def validate_pod_name(name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate Kubernetes pod name.
    
    Args:
        name: The pod name to validate
    
    Returns:
        tuple: (is_valid, error_message)
    """
    return validate_k8s_resource_name(name, "pod")

def sanitize_html(text: str) -> str:
    """
    Sanitize HTML to prevent XSS attacks.
    Escapes HTML special characters.
    
    Args:
        text: The text to sanitize
    
    Returns:
        str: Sanitized text safe for HTML output
    """
    if not text or not isinstance(text, str):
        return ""
    
    # Escape HTML special characters
    html_escape_map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    # Replace each character
    sanitized = ""
    for char in text:
        sanitized += html_escape_map.get(char, char)
    
    return sanitized

def validate_no_path_traversal(path: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that a path does not contain path traversal sequences.
    
    Args:
        path: The path to validate
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not path or not isinstance(path, str):
        return False, "Invalid path: must be a non-empty string"
    
    # Check for path traversal patterns
    dangerous_patterns = [
        '..',
        '../',
        '..\\',
        '/etc/',
        'c:/',
        'c:\\',
        '//',
        '\\\\'
    ]
    
    path_lower = path.lower()
    for pattern in dangerous_patterns:
        if pattern in path_lower:
            return False, f"Invalid path: contains path traversal pattern '{pattern}'"
    
    return True, None

def sanitize_input(value: str, input_type: str = "text") -> str:
    """
    Sanitize user input based on expected type.
    
    Args:
        value: The input value to sanitize
        input_type: Type of input ("text", "pod_name", "namespace", "url")
    
    Returns:
        str: Sanitized value
    """
    if not value or not isinstance(value, str):
        return ""
    
    if input_type in ("pod_name", "namespace"):
        # For K8s resource names, validate and return cleaned version
        is_valid, _ = validate_k8s_resource_name(value, input_type)
        if not is_valid:
            # Return empty string if invalid
            return ""
        return value.strip().lower()
    
    elif input_type == "url":
        # For URLs, validate and sanitize
        value = value.strip()
        # Basic URL validation - should start with http:// or https://
        if not value.startswith(('http://', 'https://')):
            return ""
        return value
    
    else:
        # For general text, strip whitespace and limit length
        value = value.strip()
        # Limit to reasonable length to prevent DoS
        if len(value) > 10000:
            value = value[:10000]
        return value
