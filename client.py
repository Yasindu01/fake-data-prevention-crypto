import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import jwt

BASE = "http://localhost:5000"


def get_public_key():
    resp = requests.get(BASE + "/certificate")
    cert = x509.load_pem_x509_certificate(resp.content)
    public_key = cert.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_token(token, public_key):
    return jwt.decode(token, public_key, algorithms=["RS256"])


def main():
    public_key = get_public_key()
    print("Public key extracted from server certificate")
    print("-" * 50)

    token = requests.get(BASE + "/data").json()["token"]
    try:
        payload = verify_token(token, public_key)
        print("/data           -> VALID")
        print("   payload:", payload)
    except jwt.InvalidTokenError as e:
        print("/data           -> FAILED:", e)

    print("-" * 50)

    tampered = requests.get(BASE + "/data/tampered").json()["token"]
    try:
        verify_token(tampered, public_key)
        print("/data/tampered  -> VALID (unexpected!)")
    except jwt.InvalidTokenError as e:
        print("/data/tampered  -> TAMPERED / FAILED:", e)


if __name__ == "__main__":
    main()
