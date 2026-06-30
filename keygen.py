from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os

os.makedirs("keys", exist_ok=True)
os.makedirs("certs", exist_ok=True)


def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open("keys/private_key.pem", "wb") as f:
        f.write(private_pem)

    with open("keys/public_key.pem", "wb") as f:
        f.write(public_pem)

    return private_key, public_key


def generate_certificate(private_key, public_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "fakedata-prevention.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UniMe SEC-PRJ-7E_25"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Messina"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sicilia"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    with open("certs/server_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def main():
    private_key, public_key = generate_keys()
    generate_certificate(private_key, public_key)
    print("RSA-2048 key pair generated -> keys/")
    print("Self-signed X.509 certificate generated -> certs/server_cert.pem")


if __name__ == "__main__":
    main()
