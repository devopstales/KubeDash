import os
import logging
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from lib.paths import PROJECT_ROOT

def configure_logging():
    """Configure logging with custom format and correlation ID"""
    formatter = logging.Formatter(
        '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'
    )
    
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    
    logger = logging.getLogger()
    if not logger.hasHandlers():
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    return logger

logger = configure_logging()

def generate_self_signed_cert():
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Get current folder and certs subfolder
    cert_dir = PROJECT_ROOT / 'certs'
    
    # Create certs directory if it doesn't exist
    os.makedirs(cert_dir, exist_ok=True)
    logger.info(f"Certificate directory: {cert_dir}")
    
    # Define required files
    required_files = {
        'cert.pem': 'Server Certificate',
        'key.pem': 'Server Private Key',
        'ca-cert.pem': 'CA Certificate',
        'ca-key.pem': 'CA Private Key'
    }
    
    # Check if all files exist
    all_exist = all(os.path.exists(os.path.join(cert_dir, f)) for f in required_files)
    
    if all_exist:
        logger.info("All certificate files already exist")
        return (
            os.path.join(cert_dir, 'cert.pem'),
            os.path.join(cert_dir, 'key.pem'),
            os.path.join(cert_dir, 'ca-cert.pem')
        )
    
    logger.info("Generating new self-signed certificates...")
    
    # Get namespace and service
    service_name = "kubedash-api"
    namespace = os.environ.get("POD_NAMESPACE", "default")

    # Generate CA Key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate CA Certificate
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"KubeDash CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"KubeDash"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=1)
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # Generate Server Key
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate Server Certificate
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{service_name}.{namespace}.svc"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"KubeDash"),
    ])

    alt_names = [
        f"{service_name}",
        f"{service_name}.{namespace}",
        f"{service_name}.{namespace}.svc",
        f"{service_name}.{namespace}.svc.cluster.local"
    ]
    san = x509.SubjectAlternativeName([x509.DNSName(name) for name in alt_names])

    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=1)
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # 1 year
    ).add_extension(
        san, critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # Write all files
    def write_pem(filename, content):
        with open(os.path.join(cert_dir, filename), 'wb') as f:
            f.write(content)
    
    # Write CA files
    write_pem('ca-key.pem', ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    write_pem('ca-cert.pem', ca_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ))
    
    # Write server files
    write_pem('key.pem', server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    write_pem('cert.pem', server_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ))

    logger.info("Successfully generated all certificate files")
    
    return (
        os.path.join(cert_dir, 'cert.pem'),
        os.path.join(cert_dir, 'key.pem'),
        os.path.join(cert_dir, 'ca-cert.pem')
    )