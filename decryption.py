import base64
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

def decrypt_aes(ciphertext_b64: str, key_hex: str) -> str:
    """
    Decrypts AES-CBC encrypted ciphertext.
    The IV is expected to be prepended to the ciphertext inside the base64 string.
    
    Args:
        ciphertext_b64 (str): Base64 encoded (IV + ciphertext).
        key_hex (str): Symmetric key in hex format.
        
    Returns:
        str: Decrypted plaintext.
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("AES Key must be a valid hexadecimal string.")
        
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError(f"Invalid AES key length ({len(key_bytes)} bytes). Key must be 16, 24, or 32 bytes.")
        
    try:
        combined = base64.b64decode(ciphertext_b64)
    except Exception:
        raise ValueError("Invalid Base64 format for AES ciphertext.")
        
    if len(combined) < AES.block_size:
        raise ValueError("Ciphertext is too short to contain a valid IV.")
        
    iv = combined[:AES.block_size]
    ciphertext = combined[AES.block_size:]
    
    try:
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, AES.block_size, style='pkcs7')
        return decrypted.decode('utf-8')
    except (ValueError, KeyError) as e:
        raise ValueError("Decryption failed. This is likely due to an incorrect key or corrupted ciphertext.")

def decrypt_des(ciphertext_b64: str, key_hex: str) -> str:
    """
    Decrypts DES-CBC encrypted ciphertext.
    The IV is expected to be prepended to the ciphertext inside the base64 string.
    
    Args:
        ciphertext_b64 (str): Base64 encoded (IV + ciphertext).
        key_hex (str): Symmetric key in hex format.
        
    Returns:
        str: Decrypted plaintext.
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("DES Key must be a valid hexadecimal string.")
        
    if len(key_bytes) != 8:
        raise ValueError(f"Invalid DES key length ({len(key_bytes)} bytes). Key must be exactly 8 bytes (16 hex characters).")
        
    try:
        combined = base64.b64decode(ciphertext_b64)
    except Exception:
        raise ValueError("Invalid Base64 format for DES ciphertext.")
        
    if len(combined) < DES.block_size:
        raise ValueError("Ciphertext is too short to contain a valid IV.")
        
    iv = combined[:DES.block_size]
    ciphertext = combined[DES.block_size:]
    
    try:
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, DES.block_size, style='pkcs7')
        return decrypted.decode('utf-8')
    except (ValueError, KeyError) as e:
        raise ValueError("Decryption failed. This is likely due to an incorrect key or corrupted ciphertext.")

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

def decrypt_rsa(ciphertext_b64: str, private_key_pem: str) -> str:
    """
    Decrypts RSA PKCS1_OAEP encrypted ciphertext.
    
    Args:
        ciphertext_b64 (str): Base64 encoded ciphertext.
        private_key_pem (str): PEM-formatted RSA private key.
        
    Returns:
        str: Decrypted plaintext.
    """
    try:
        normalized_key = normalize_pem(private_key_pem)
        private_key = RSA.import_key(normalized_key)
    except Exception as e:
        raise ValueError(f"Invalid RSA Private Key format. Must be a valid PEM key. Error: {str(e)}")
        
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
    except Exception:
        raise ValueError("Invalid Base64 format for RSA ciphertext.")
        
    try:
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(ciphertext_bytes)
        return decrypted.decode('utf-8')
    except (ValueError, TypeError) as e:
        raise ValueError("Decryption failed. Ensure you are using the correct private key corresponding to the public key used for encryption.")
