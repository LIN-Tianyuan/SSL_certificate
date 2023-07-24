import datetime
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

COUNTRY_NAME = "FR"
STATE_OR_PROVINCE_NAME = "Ile de France"
LOCALITY_NAME = "Paris"
ORGANIZATION_NAME = "GROUPE SOCIETE GENERALE"
ORGANIZATIONAL_UNIT_NAME = "MARK BTO TEC DAT"
COMMON_NAME = "dat-foobar-dev"
DNS_NAME = "dat-foobar-dev.fr.world.socgen"


def make_certificate(dns_fqdn: str, with_password: bool):
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


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

    return cert


cert = make_certificate(DNS_NAME, False)
print(cert)

with open("P:\\Alex\\Test1\\certificate.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
