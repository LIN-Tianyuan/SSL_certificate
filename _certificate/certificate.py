import datetime
import secrets
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


from _certificate._domain import is_valid_domain
from _certificate._logging import get_logger

COUNTRY_NAME = "FR"
STATE_OR_PROVINCE_NAME = "Ile de France"
LOCALITY_NAME = "Paris"
ORGANIZATION_NAME = "GROUPE SOCIETE GENERALE"
ORGANIZATIONAL_UNIT_NAME = "MARK BTO TEC DAT"
COMMON_NAME = "dat-foobar-dev"
DNS_NAME = "dat-foobar-dev.fr.world.socgen"

logger = get_logger("pki")
class Certificate:
    ca_key: str
    ca_cert: str
    ca_chain: str
    password: Optional[str]


def make_certificate(dns_fqdn: str, with_password: bool) -> Certificate:
    """Build and register (sign) a SSL _certificate"""

    assert is_valid_domain(dns_fqdn), f"Invalid domain name: '{dns_fqdn}'"
    name, dns_zone = dns_fqdn.split(".", maxsplit=1)

    logger.info(
        f"Building _certificate for '{dns_fqdn}'"
        f"({'with' if with_password else 'without'} password) ..."
    )
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    logger.info(f"DN for '{dns_fqdn}': COUNTRY_NAME             : {COUNTRY_NAME}")
    logger.info(f"DN for '{dns_fqdn}': STATE_OR_PROVINCE_NAME   : {STATE_OR_PROVINCE_NAME}")
    logger.info(f"DN for '{dns_fqdn}': LOCALITY_NAME            : {LOCALITY_NAME}")
    logger.info(f"DN for '{dns_fqdn}': ORGANIZATION_NAME        : {ORGANIZATION_NAME}")
    logger.info(f"DN for '{dns_fqdn}': ORGANIZATIONAL_UNIT_NAME : {ORGANIZATIONAL_UNIT_NAME}")
    logger.info(f"DN for '{dns_fqdn}': COMMON_NAME              : {dns_fqdn}")

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME),
        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ORGANIZATIONAL_UNIT_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, dns_fqdn)
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this _certificate for
            x509.DNSName(DNS_NAME)
        ]),
        critical=False
        # Sign the CSR with our private key
    ).sign(key, hashes.SHA256(), default_backend())

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")
    ).decode("utf8")

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    cert_pem = clean_pem_cert(

    )
    if with_password:
        password = secrets.token_urlsafe(16)
        encryption_algorithm = serialization.BestAvailableEncryption(
            password.encode("utf8")
        )
    else:
        password = None
        encryption_algorithm = serialization.NoEncryption()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME),
        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME)
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(DNS_NAME)]),
        critical=False
    ).sign(key, hashes.SHA256())

    logger.info(f"Certificate for '{dns_fqdn}' created.")

    return cert


def clean_pem_cert(text: str) -> str:
    """Clean a PEM _certificate of any comments/headers"""
    lines = text.splitlines()
    results = []
    start: bool = False
    for line in lines:
        if not line.strip():
            continue
        if line.lstrip().startswith('#'):
            continue
        if line.strip() == "-----BEGIN CERTIFICATE-----":
            start = True
        if line.strip() == "-----END CERTIFICATE-----":
            results.append(line)
            start = False
        if not start:
            continue
        else:
            results.append(line)
    return "\n".join(results)

print(make_certificate("dat-foobar-dev.fr.world.socgen", False))

