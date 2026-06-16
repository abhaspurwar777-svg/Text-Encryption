# SecureText Encryption System

An interactive, full-stack cybersecurity web application designed to demonstrate the practical application of symmetric (AES, DES) and asymmetric (RSA) cryptography. The platform includes a military-grade dark cybersecurity dashboard, console output logging, and operation tracking stored in a local SQLite database.

---

## Technical Stack & Dependencies

- **Backend**: Python 3, Flask, SQLite3
- **Cryptography**: `pycryptodome` (handles padding, block modes, and key formats)
- **Frontend**: Responsive Single-Page Application built using HTML5, Vanilla CSS3 (glassmorphic layout, glowing neon accents, and keyframe animations), and Vanilla JavaScript (Fetch API, DOM rendering, simulated console logs, and custom toasts).

---

## Directory Structure

```text
.antigravity/
├── app.py                   # Main Flask API and Static Server
├── key_management.py        # Generates AES, DES, and RSA keys
├── encryption.py            # Encryption logic (AES-CBC, DES-CBC, RSA-OAEP)
├── decryption.py            # Decryption logic (AES-CBC, DES-CBC, RSA-OAEP)
├── database.py              # SQLite3 logging engine and schemas
├── test_crypto.py           # Automated terminal unit test suite
├── securetext.db            # SQLite database file (auto-generated on startup)
├── README.md                # System documentation
└── static/                  # Frontend UI assets folder
    ├── index.html           # Main dashboard skeleton layout
    ├── style.css            # Custom CSS definitions & animations
    └── script.js            # Frontend logic and API controller
```

---

## Cryptographic Design

### 1. Advanced Encryption Standard (AES)
- **Mode**: AES-256 in Cipher Block Chaining (CBC) mode.
- **Key**: 256-bit (32 bytes), represented as a 64-character hexadecimal string.
- **Initialization Vector (IV)**: A cryptographically secure random 128-bit (16 bytes) IV is generated for each operation. The IV is prepended to the ciphertext byte array (`IV + Ciphertext`) and encoded as a base64 string.
- **Padding**: PKCS7 padding.

### 2. Data Encryption Standard (DES)
- **Mode**: DES in CBC mode. Included for legacy testing and educational purposes.
- **Key**: 64-bit (8 bytes, 56 effective bits), represented as a 16-character hexadecimal string.
- **Initialization Vector (IV)**: Random 64-bit (8 bytes) IV prepended to the ciphertext and base64-encoded.
- **Warning**: A prominent security warning is displayed on the dashboard when DES is selected, indicating that DES is obsolete and vulnerable to brute-force attacks.

### 3. Rivest-Shamir-Adleman (RSA)
- **Key Size**: RSA-2048 keys in standard PEM format.
- **Padding**: Optimal Asymmetric Encryption Padding (PKCS1_OAEP).
- **Usage**:
  - **Encryption**: Done with the public key. Fails if the plaintext size exceeds 214 bytes (key size of 256 bytes minus 42 bytes for OAEP padding overhead).
  - **Decryption**: Done with the private key.

---

## Installation & Setup

1. **Clone or navigate** to the project directory:
   ```bash
   cd c:\Users\nanda\.antigravity
   ```

2. **Install the dependencies**:
   ```bash
   python -m pip install pycryptodome flask
   ```

3. **Verify the installation**:
   To run the programmatic backend validation test suite, execute:
   ```bash
   python test_crypto.py
   ```

4. **Start the Flask server**:
   ```bash
   python app.py
   ```
   The application will start on `http://127.0.0.1:5000`.

5. **Access the Dashboard**:
   Open a browser and navigate to `http://127.0.0.1:5000`.

---

## API Endpoints

### 1. `POST /api/generate-key`
Generates cryptographically secure keys.
- **Payload**: `{ "algorithm": "AES" | "DES" | "RSA" }`
- **Response**:
  - Symmetric (AES/DES): `{ "status": "success", "key": "<hex_string>" }`
  - Asymmetric (RSA): `{ "status": "success", "public_key": "<pem>", "private_key": "<pem>" }`

### 2. `POST /api/encrypt`
Encrypts a plaintext message. If the key is omitted, it auto-generates one and returns it.
- **Payload**: `{ "text": "<msg>", "algorithm": "AES" | "DES" | "RSA", "key": "<key_or_pem_optional>" }`
- **Response**: `{ "status": "success", "ciphertext": "<base64_str>", "algorithm": "<algo>", "generated_keys": { "key": "...", "note": "..." } }`

### 3. `POST /api/decrypt`
Decrypts a base64 ciphertext message using the provided key.
- **Payload**: `{ "ciphertext": "<base64_str>", "algorithm": "AES" | "DES" | "RSA", "key": "<key_or_pem_required>" }`
- **Response**: `{ "status": "success", "plaintext": "<recovered_msg>", "algorithm": "<algo>" }`

### 4. `GET /api/history`
Retrieves recent transaction logs from the SQLite database.
- **Response**: `{ "status": "success", "history": [ { "id": 1, "timestamp": "...", "algorithm": "AES", "operation": "ENCRYPT", "input_length": 45, "key_preview": "AES-256 (...", "status": "SUCCESS", "error_message": null } ] }`

### 5. `POST /api/history/clear`
Clears all transaction logs.
- **Response**: `{ "status": "success", "message": "Transaction logs successfully cleared." }`

---

## Cybersecurity Features & Design Best Practices

- **Zero plaintext logging**: The SQLite database only stores transaction metadata (algorithm, operation type, character counts, status, and truncated key previews). Raw secret messages or key details never touch the database.
- **Responsive Layout**: Designed for seamless usage across modern desktops, tablets, and mobile devices.
- **Dynamic Terminal Feedback**: Simulated shell console logs reflect active requests, key generation, database writes, and server responsiveness in real-time.
- **Security Validation warnings**: Alert messages are displayed if users input unsafe configurations (e.g. using DES, or supplying wrong key sizes).
