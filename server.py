from flask import Flask, jsonify, send_file
from cryptography.hazmat.primitives import serialization
import jwt
import datetime
import json
import base64

app = Flask(__name__)

with open("keys/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)


def sample_payload():
    return {
        "sensor_id": "TEMP-SENS-014",
        "location": "Messina-Lab-A",
        "value": 23.7,
        "unit": "C",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
    }


def b64url_decode(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@app.route("/certificate")
def certificate():
    return send_file("certs/server_cert.pem", mimetype="application/x-pem-file")


@app.route("/data")
def data():
    token = jwt.encode(sample_payload(), private_key, algorithm="RS256")
    return jsonify({"token": token})


@app.route("/data/tampered")
def data_tampered():
    token = jwt.encode(sample_payload(), private_key, algorithm="RS256")
    header_b64, payload_b64, signature_b64 = token.split(".")

    payload = json.loads(b64url_decode(payload_b64))
    payload["value"] = 999.9
    payload["sensor_id"] = "HACKED-SENSOR"

    new_payload_b64 = b64url_encode(json.dumps(payload).encode())
    tampered_token = header_b64 + "." + new_payload_b64 + "." + signature_b64

    return jsonify({"token": tampered_token})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
