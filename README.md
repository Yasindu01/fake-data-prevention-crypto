# SEC-PRJ-7E_25 — Fake Data Prevention with Conventional Cryptotools

A client–server system that prevents fake / tampered data using conventional
cryptographic tools: **RSA-2048 digital signatures**, a **self-signed X.509
certificate**, and **JSON Web Tokens (JWT, RS256)**.

The server signs sensor data with its RSA private key and issues it as a JWT.
The client fetches the server's X.509 certificate, extracts the public key, and
verifies the JWT signature. If the data is modified after signing, verification
fails — proving the data is fake.

> University of Messina — System Security course.

## How it works

1. The server holds an RSA-2048 private key and a self-signed X.509 certificate.
2. `GET /data` returns a sensor payload signed as a JWT (RS256).
3. The client downloads the certificate, extracts the public key, and verifies
   the JWT. A valid signature means the data is authentic and untampered.
4. `GET /data/tampered` returns a JWT whose payload was modified **after**
   signing while keeping the original signature — verification fails, exposing
   the forgery.

## File structure

```
sec_prj_7e/
├── keygen.py          generates RSA-2048 key pair + self-signed X.509 cert
├── server.py          Flask REST API — signs data, issues JWTs
├── client.py          verifies JWT signature using the server's certificate
├── tamper_test.py     inline test suite (valid + tamper scenarios)
├── keys/              RSA keys (generated, git-ignored)
│   ├── private_key.pem
│   └── public_key.pem
└── certs/             X.509 certificate (generated, git-ignored)
    └── server_cert.pem
```

The `keys/` and `certs/` folders are generated locally and are **not committed**
(the private key must never be shared). Run `keygen.py` to create them.

## Requirements

```
pip install cryptography pyjwt flask requests
```

## How to run

1. Generate the keys and certificate:

   ```
   python keygen.py
   ```

2. Start the server (terminal 1):

   ```
   python server.py
   ```

3. Run the client to verify the end-to-end flow (terminal 2):

   ```
   python client.py
   ```

   Expected output:

   ```
   /data           -> VALID
   /data/tampered  -> TAMPERED / FAILED: Signature verification failed
   ```

4. Run the standalone tamper test suite (no server needed):

   ```
   python tamper_test.py
   ```

   Tests: valid data, tampered value, tampered sensor_id, wrong key, expired
   token — each prints PASS/FAIL.

## Endpoints

| Method | Path             | Description                                       |
|--------|------------------|---------------------------------------------------|
| GET    | `/certificate`   | Serves the server's X.509 certificate (PEM).      |
| GET    | `/data`          | Signed sensor payload as a JWT (RS256).           |
| GET    | `/data/tampered` | JWT modified after signing — fails verification.  |
