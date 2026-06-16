import base64
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

def encrypt_aes(plaintext: str, key_hex: str) -> str:
    """
    Encrypts plaintext using AES-CBC (256-bit key by default, supports 128/192/256 bits).
    The IV is prepended to the ciphertext and the result is returned as a base64 string.
    
    Args:
        plaintext (str): Message to encrypt.
        key_hex (str): Symmetric key in hex format.
        
    Returns:
        str: Base64 encoded (IV + ciphertext).
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("AES Key must be a valid hexadecimal string.")
        
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError(f"Invalid AES key length ({len(key_bytes)} bytes). Key must be 16, 24, or 32 bytes (32, 48, or 64 hex characters).")
        
    # Pad plaintext using PKCS#7 to match AES block size (16 bytes)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size, style='pkcs7')
    
    # Generate random IV and create CBC cipher
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ciphertext = cipher.encrypt(padded_data)
    
    # Prepend IV to ciphertext for easy decryption retrieval
    combined = cipher.iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def encrypt_des(plaintext: str, key_hex: str) -> str:
    """
    Encrypts plaintext using DES-CBC.
    The IV is prepended to the ciphertext and the result is returned as a base64 string.
    
    Args:
        plaintext (str): Message to encrypt.
        key_hex (str): Symmetric key in hex format (must be 8 bytes / 16 hex characters).
        
    Returns:
        str: Base64 encoded (IV + ciphertext).
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("DES Key must be a valid hexadecimal string.")
        
    if len(key_bytes) != 8:
        raise ValueError(f"Invalid DES key length ({len(key_bytes)} bytes). Key must be exactly 8 bytes (16 hex characters).")
        
    # Pad plaintext using PKCS#7 to match DES block size (8 bytes)
    padded_data = pad(plaintext.encode('utf-8'), DES.block_size, style='pkcs7')
    
    # Generate random IV and create CBC cipher
    cipher = DES.new(key_bytes, DES.MODE_CBC)
    ciphertext = cipher.encrypt(padded_data)
    
    # Prepend IV (8 bytes) to ciphertext
    combined = cipher.iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def normalize_pem(pem_str: str) -> str:
    """
    Normalizes a PEM key string that may have had its newlines stripped 
    or flattened (e.g. replaced by spaces) when pasted into a single-line input field.
    """
    pem_str = pem_str.strip()
    if not pem_str:
        return pem_str

    # If it has newlines and the standard boundaries, it is likely already valid
    if "\n" in pem_str and "-----BEGIN" in pem_str:
        return pem_str

    # Clean up standard spaces/whitespace variations if it was flattened
    normalized = " ".join(pem_str.split())

    headers = [
        ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
        ("-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"),
        ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
        ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
    ]

    for header, footer in headers:
        if header in normalized and footer in normalized:
            # Extract the base64 content
            start_idx = normalized.find(header) + len(header)
            end_idx = normalized.find(footer)
            base64_content = normalized[start_idx:end_idx].replace(" ", "").replace("\r", "").replace("\n", "")
            
            # Reconstruct the PEM formatting with 64-character lines
            lines = [base64_content[i:i+64] for i in range(0, len(base64_content), 64)]
            return f"{header}\n" + "\n".join(lines) + f"\n{footer}"
            
    return pem_str

def encrypt_rsa(plaintext: str, public_key_pem: str) -> str:
    """
    Encrypts plaintext using RSA with PKCS1_OAEP padding.
    The result is returned as a base64 string.
    
    Args:
        plaintext (str): Message to encrypt.
        public_key_pem (str): PEM-formatted RSA public key.
        
    Returns:
        str: Base64 encoded ciphertext.
    """
    try:
        normalized_key = normalize_pem(public_key_pem)
        public_key = RSA.import_key(normalized_key)
    except Exception as e:
        raise ValueError(f"Invalid RSA Public Key format. Must be a valid PEM key. Error: {str(e)}")
        
    # PKCS1_OAEP padding uses a portion of key size. 
    # For a 2048-bit key (256 bytes), max plaintext length is 256 - 2 - 2 * hash_length.
    # For SHA-1 (default in pycryptodome OAEP), hash_len = 20, max plaintext is 214 bytes.
    max_len = public_key.size_in_bytes() - 42
    plaintext_bytes = plaintext.encode('utf-8')
    if len(plaintext_bytes) > max_len:
        raise ValueError(f"Plaintext is too long ({len(plaintext_bytes)} bytes) for RSA key size. Maximum size is {max_len} bytes.")
        
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext_bytes)
    return base64.b64encode(ciphertext).decode('utf-8')
