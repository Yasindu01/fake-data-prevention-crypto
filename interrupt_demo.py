import jwt
import json
import base64
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


server_private = load_private("keys/private_key.pem")
client_private = load_private("keys/client_private_key.pem")
client_public = load_public("keys/client_public_key.pem")

with open("certs/server_cert.pem", "rb") as f:
    server_public = x509.load_pem_x509_certificate(f.read()).public_key()


def oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_data(data):
    encrypted = client_public.encrypt(json.dumps(data).encode(), oaep())
    return base64.b64encode(encrypted).decode()


def decrypt_data(encrypted_b64):
    raw = client_private.decrypt(base64.b64decode(encrypted_b64), oaep())
    return json.loads(raw.decode())


def b64url_decode(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def send_data():
    sensor_data = {
        "sensor_id": "TEMP-SENS-014",
        "location": "Messina-Lab-A",
        "value": 23.7,
        "unit": "C",
    }
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "encrypted_data": encrypt_data(sensor_data),
        "timestamp": now.isoformat(),
        "iat": now,
        "exp": now + datetime.timedelta(minutes=5),
    }
    return jwt.encode(payload, server_private, algorithm="RS256")


def rebuild(token, payload):
    header_b64, _, signature_b64 = token.split(".")
    new_payload_b64 = b64url_encode(json.dumps(payload).encode())
    return header_b64 + "." + new_payload_b64 + "." + signature_b64


def intercept(token):
    header_b64, payload_b64, signature_b64 = token.split(".")
    payload = json.loads(b64url_decode(payload_b64))

    print("\n[MIDDLE] You intercepted the message. This is what you can see:")
    for key, value in payload.items():
        print("   ", key, "=", str(value)[:50])

    print("\n[MIDDLE] What do you want to do?")
    print("  1. Forward it unchanged")
    print("  2. Edit a field")
    print("  3. Inject my own fake sensor value")
    choice = input("> ").strip()

    if choice == "2":
        field = input("Which field? (" + ", ".join(payload.keys()) + "): ").strip()
        if field not in payload:
            print("No such field, forwarding unchanged.")
            return token
        payload[field] = input("New value: ")
        return rebuild(token, payload)

    if choice == "3":
        raw = input("Fake temperature value: ").strip()
        try:
            fake_value = float(raw)
        except ValueError:
            print("Not a number, forwarding unchanged.")
            return token
        fake_data = {
            "sensor_id": "TEMP-SENS-014",
            "location": "Messina-Lab-A",
            "value": fake_value,
            "unit": "C",
        }
        payload["encrypted_data"] = encrypt_data(fake_data)
        print("Fake value encrypted with the client's PUBLIC key and swapped in.")
        return rebuild(token, payload)

    return token


def receive(token):
    print("\n[RECEIVER] Checking the signature with the server's public key...")
    try:
        payload = jwt.decode(token, server_public, algorithms=["RS256"])
    except jwt.InvalidTokenError as e:
        print("[RECEIVER] RESULT: NOT ORIGINAL - rejected (" + str(e) + ")")
        return
    print("[RECEIVER] Signature valid. Decrypting with the client's private key...")
    data = decrypt_data(payload["encrypted_data"])
    print("[RECEIVER] RESULT: ORIGINAL - accepted")
    print("   data:", data)


def main():
    print("=" * 55)
    print("  SENDER -> MIDDLE (you) -> RECEIVER")
    print("=" * 55)
    while True:
        print("\n[SENDER] Server signs and encrypts the sensor data.")
        token = send_data()
        token = intercept(token)
        receive(token)
        again = input("\nTry again? (y/n): ").strip().lower()
        if again != "y":
            break


if __name__ == "__main__":
    main()
