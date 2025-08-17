from flask import Flask
from . import create_app
from .lib.cert_utils import generate_self_signed_cert


#####################################################################
# __main__
#####################################################################

if __name__ == "__main__":
    app = create_app()
    
    # Generate self-signed certs if needed
    cert_path, key_path, ca_cert_path = generate_self_signed_cert()

    Flask.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_context=(cert_path, key_path)
    )