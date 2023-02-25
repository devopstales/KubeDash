#!/usr/bin/env python3
from itsdangerous import base64_encode, base64_decode
import re

##############################################################
## base64 decode
##############################################################
def j2_b64decode(value):
    decoded_value = str(base64_decode(value), 'UTF-8')
    return decoded_value

##############################################################
## base64 encode
##############################################################
def j2_b64encode(value):
    encoded_value = str(base64_encode(value), 'UTF-8')
    return encoded_value

##############################################################
## split uppercase
##############################################################
def split_uppercase(value):
    split_value = re.findall('.[^A-Z]*', value)
    return split_value
