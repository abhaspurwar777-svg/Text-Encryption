import secrets
from Crypto.PublicKey import RSA

def generate_aes_key() -> str:
    """
    Generates a cryptographically secure 256-bit (32-byte) AES key
    returned as a 64-character hexadecimal string.
    """
    # 32 bytes = 256 bits key size
    random_bytes = secrets.token_bytes(32)
    return random_bytes.hex()

def generate_des_key() -> str:
    """
    Generates a cryptographically secure 56-bit (8-byte key, 64-bit total) DES key
    returned as a 16-character hexadecimal string.
    """
    # DES uses 8-byte keys (56 effective bits + 8 parity bits, though pycryptodome expects 8 bytes)
    random_bytes = secrets.token_bytes(8)
    return random_bytes.hex()

def generate_rsa_keypair(key_size: int = 2048) -> tuple[str, str]:
    """
    Generates a 2048-bit RSA public/private key pair.
    Returns:
        tuple: (public_key_pem, private_key_pem) as strings.
    """
    key = RSA.generate(key_size)
    private_key_pem = key.export_key().decode('utf-8')
    public_key_pem = key.publickey().export_key().decode('utf-8')
    return public_key_pem, private_key_pem
