from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import datetime
import json
import base64

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def build_payload(value):
    return {
        "sensor_id": "TEMP-SENS-014",
        "location": "Messina-Lab-A",
        "value": value,
        "unit": "C",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
    }


def b64url_decode(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign(value):
    token = jwt.encode(build_payload(value), private_key, algorithm="RS256")
    print("\nData signed into a JWT token:")
    print(token[:70] + "...")
    return token


def verify(token):
    try:
        payload = jwt.decode(token, public_pem, algorithms=["RS256"])
        print("\nRESULT: VALID - signature verified, data is authentic")
        print("Data:", payload["sensor_id"], "value =", payload["value"])
    except jwt.InvalidTokenError as e:
        print("\nRESULT: REJECTED - " + str(e))


def tamper(token, new_value):
    header_b64, payload_b64, signature_b64 = token.split(".")
    payload = json.loads(b64url_decode(payload_b64))
    old = payload["value"]
    payload["value"] = new_value
    new_payload_b64 = b64url_encode(json.dumps(payload).encode())
    print("\nAttacker changed value from", old, "to", new_value, "(signature kept unchanged)")
    return header_b64 + "." + new_payload_b64 + "." + signature_b64


def menu():
    print("=" * 55)
    print("  SEC-PRJ-7E_25  Fake Data Prevention - Interactive Demo")
    print("=" * 55)
    while True:
        print("\nChoose an option:")
        print("  1. Sign and verify VALID data")
        print("  2. Sign, then TAMPER, then verify (attack demo)")
        print("  3. Enter your own sensor value and sign it")
        print("  4. Quit")
        choice = input("> ").strip()

        if choice == "1":
            token = sign(23.7)
            verify(token)
        elif choice == "2":
            token = sign(23.7)
            bad = tamper(token, 999.9)
            verify(bad)
        elif choice == "3":
            raw = input("Enter a temperature value: ").strip()
            try:
                value = float(raw)
                token = sign(value)
                verify(token)
            except ValueError:
                print("Please enter a number.")
        elif choice == "4":
            print("Goodbye.")
            break
        else:
            print("Invalid choice, try 1-4.")


if __name__ == "__main__":
    menu()
