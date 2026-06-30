from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import datetime
import json
import base64


def make_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def base_payload():
    return {
        "sensor_id": "TEMP-SENS-014",
        "location": "Messina-Lab-A",
        "value": 23.7,
        "unit": "C",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
    }


def b64url_decode(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def tamper(token, changes):
    header_b64, payload_b64, signature_b64 = token.split(".")
    payload = json.loads(b64url_decode(payload_b64))
    payload.update(changes)
    new_payload_b64 = b64url_encode(json.dumps(payload).encode())
    return header_b64 + "." + new_payload_b64 + "." + signature_b64


def report(name, passed):
    status = "PASS" if passed else "FAIL"
    print("[" + status + "] " + name)


def test_valid(private_key, public_pem):
    token = jwt.encode(base_payload(), private_key, algorithm="RS256")
    try:
        jwt.decode(token, public_pem, algorithms=["RS256"])
        report("valid data accepted", True)
    except jwt.InvalidTokenError:
        report("valid data accepted", False)


def test_tampered_value(private_key, public_pem):
    token = jwt.encode(base_payload(), private_key, algorithm="RS256")
    bad = tamper(token, {"value": 999.9})
    try:
        jwt.decode(bad, public_pem, algorithms=["RS256"])
        report("tampered value rejected", False)
    except jwt.InvalidTokenError:
        report("tampered value rejected", True)


def test_tampered_sensor_id(private_key, public_pem):
    token = jwt.encode(base_payload(), private_key, algorithm="RS256")
    bad = tamper(token, {"sensor_id": "HACKED-SENSOR"})
    try:
        jwt.decode(bad, public_pem, algorithms=["RS256"])
        report("tampered sensor_id rejected", False)
    except jwt.InvalidTokenError:
        report("tampered sensor_id rejected", True)


def test_wrong_key(private_key, public_pem):
    token = jwt.encode(base_payload(), private_key, algorithm="RS256")
    _, other_public_pem = make_keys()
    try:
        jwt.decode(token, other_public_pem, algorithms=["RS256"])
        report("wrong key rejected", False)
    except jwt.InvalidTokenError:
        report("wrong key rejected", True)


def test_expired(private_key, public_pem):
    payload = base_payload()
    payload["iat"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)
    payload["exp"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    token = jwt.encode(payload, private_key, algorithm="RS256")
    try:
        jwt.decode(token, public_pem, algorithms=["RS256"])
        report("expired token rejected", False)
    except jwt.ExpiredSignatureError:
        report("expired token rejected", True)
    except jwt.InvalidTokenError:
        report("expired token rejected", True)


def main():
    private_key, public_pem = make_keys()
    print("Running tamper detection tests")
    print("=" * 40)
    test_valid(private_key, public_pem)
    test_tampered_value(private_key, public_pem)
    test_tampered_sensor_id(private_key, public_pem)
    test_wrong_key(private_key, public_pem)
    test_expired(private_key, public_pem)
    print("=" * 40)


if __name__ == "__main__":
    main()
