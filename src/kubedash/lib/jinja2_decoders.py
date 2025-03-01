#!/usr/bin/env python3
from itsdangerous import base64_encode, base64_decode
import re

##############################################################
## base64 decode
##############################################################
def j2_b64decode(value: str) -> str:
    """Jinja2 base64 decode
    
    Args:
        value (str): Base64 encoded value
        
    Returns:
        decoded_value (str): Decoded value
    """
    decoded_value = str(base64_decode(value), 'UTF-8')
    return decoded_value

##############################################################
## base64 encode
##############################################################
def j2_b64encode(value: str) -> str:
    """Jinja2 base64 encoder
    
    Args:
        value (str): String to encode
        
    Returns:
        encoded_value (str): Base64 encoded value
    """
    encoded_value = str(base64_encode(value), 'UTF-8')
    return encoded_value

##############################################################
## split uppercase
##############################################################
def split_uppercase(value: str) -> str:
    """Split a string by uppercase letters
    
    Args:
        value (str): Input string
        
    Returns:
        split_value (str): Space separeted list 
    """
    split_value = re.findall('.[^A-Z]*', value)
    return split_value
