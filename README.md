File encryption: AES-256-GCM

Key wrapping: ECIES


File Encryption (AES-256-GCM) is the most intuitive one. You have a file, you don't want the server to read it, so you encrypt it with a random key called the File Encryption Key (FEK) before uploading. The server receives and stores only ciphertext — scrambled bytes it cannot read. This solves the "server reads your files" problem.
But it immediately creates a new problem: where does the FEK live? If you just stored the FEK alongside the ciphertext on the server, the server could decrypt everything trivially. You can't store it in plaintext anywhere the server can see.

Key wrapping done via ECIES. ECDH will generate key pair using the NIST Elliptical Curve. Public key will be stored by server, private will be stored by user. ECC is more efficient than RSA since it can achieve similar security with significantly smaller keysize. Since we are wrapping the file key (small size data), ECC will be suitable.

---

# Steps to get the client and server working

## Client

1. Generate a server.key and server.crt
```openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout server.key -out server.crt -days 365 -nodes -addext "subjectAltName=IP:127.0.0.1"```

2. Install the requirements
`pip install -r requirements.txt`

2. Run the client
`python client_runtime.py`
