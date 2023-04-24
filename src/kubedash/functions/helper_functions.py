import logging, re, time
from flask import flash, json
from decimal import Decimal, InvalidOperation

##############################################################
## Helper Functions
##############################################################

def get_logger(name):
    logger = logging.getLogger(name)
    logging.basicConfig(
            level="INFO",
            format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
        )
    return logger

def ErrorHandler(logger, error, action):
    if hasattr(error, '__iter__'):
        if 'status' in error:
            if error.status == 401:
                flash("401 - Unauthorized: User cannot connect to Kubernetes", "danger")
            elif error.status == 403:
                flash("403 - Forbidden: User cannot %s" % action, "danger")
        else:
            flash(action, "danger")
            logger.error("Exception: %s \n" % action)
    else:
        flash(action, "danger")
        logger.error("Exception: %s \n" % action)

def email_check(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False
    
def parse_quantity(quantity):
    """
    Parse kubernetes canonical form quantity like 200Mi to a decimal number.
    Supported SI suffixes:
    base1024: Ki | Mi | Gi | Ti | Pi | Ei
    base1000: n | u | m | "" | k | M | G | T | P | E
    See https://github.com/kubernetes/apimachinery/blob/master/pkg/api/resource/quantity.go
    Input:
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

def calPercent(x, y, integer = False):
    """
    Percentage of 4 out of 19: 4 / 19 * 100
    """
    percent = x / y * 100
   
    if integer:
        return int(percent)
    return percent

def find_values_in_json(id, json_repr):
    results = list()

    def _decode_dict(a_dict):
        try:
            results.append(a_dict[id])
        except KeyError:
            pass
        return a_dict

    json.loads(json_repr, object_hook=_decode_dict) # Return value ignored.
    return results

class cache_request_with_timeout:
    DEFAULT_TIMEOUT = 60

    def __init__(self, timeout=None):
        self.__cache = {}
        self.__timeout = timeout

    def __call__(self, f):
        def decorator(*args, **kwargs):
            timeout = self.__timeout or cache_request_with_timeout.DEFAULT_TIMEOUT
            key = (args, frozenset(kwargs))

            if key in self.__cache:
                ts, result = self.__cache[key]
                if (time.time() - ts) < timeout:
                    return result

            result = f(*args, **kwargs)
            self.__cache[key] = (time.time(), result)

            return result
        return decorator