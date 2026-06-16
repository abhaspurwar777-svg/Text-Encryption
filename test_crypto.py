import sys
import os

# Add the directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import key_management
import encryption
import decryption
import database

def run_tests():
    print("=" * 60)
    print("STARTING SECURITY MODULE VERIFICATION TESTS")
    print("=" * 60)
    
    # 1. Initialize and clear database
    print("\n[DB] Initializing and clearing test database...")
    database.init_db()
    database.clear_history()
    print("[DB] Database cleared. History log count:", len(database.get_history()))
    
    # 2. Test Key Generation
    print("\n[KEYS] Testing automatic key generation...")
    
    aes_key = key_management.generate_aes_key()
    print(f"  - Generated AES key (hex): {aes_key} (Length: {len(aes_key)} chars)")
    assert len(aes_key) == 64, "AES-256 key hex string should be 64 characters."
    
    des_key = key_management.generate_des_key()
    print(f"  - Generated DES key (hex): {des_key} (Length: {len(des_key)} chars)")
    assert len(des_key) == 16, "DES key hex string should be 16 characters."
    
    pub_pem, priv_pem = key_management.generate_rsa_keypair()
    print(f"  - Generated RSA Public key PEM starts with: {pub_pem[:30]}...")
    print(f"  - Generated RSA Private key PEM starts with: {priv_pem[:30]}...")
    assert "BEGIN PUBLIC KEY" in pub_pem, "RSA Public key should be in PEM format."
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem, "RSA Private key should be in PEM format."
    
    print("[KEYS] Key generation tests passed.")
    
    # 3. Test AES Encryption and Decryption
    print("\n[AES] Testing AES-CBC encryption/decryption...")
    message = "Classified: Operation Antigravity is a success."
    
    ciphertext = encryption.encrypt_aes(message, aes_key)
    print(f"  - Plaintext: {message}")
    print(f"  - Ciphertext (Base64): {ciphertext}")
    
    decrypted = decryption.decrypt_aes(ciphertext, aes_key)
    print(f"  - Decrypted: {decrypted}")
    assert decrypted == message, "AES Decryption should recover the original plaintext."
    
    # Manually log to test database operation
    database.add_history_log("AES", "ENCRYPT", len(message), f"AES-256 ({aes_key[:8]}...)", "SUCCESS")
    database.add_history_log("AES", "DECRYPT", len(ciphertext), f"AES-256 ({aes_key[:8]}...)", "SUCCESS")
    
    # Verify database log for AES
    logs = database.get_history()
    assert len(logs) == 2, f"Database should contain 2 entries. Found: {len(logs)}"
    print(f"  - Log 1: {logs[0]['operation']} using {logs[0]['algorithm']} Status: {logs[0]['status']}")
    print(f"  - Log 2: {logs[1]['operation']} using {logs[1]['algorithm']} Status: {logs[1]['status']}")
    
    print("[AES] AES tests passed.")
    
    # 4. Test DES Encryption and Decryption
    print("\n[DES] Testing DES-CBC encryption/decryption...")
    ciphertext_des = encryption.encrypt_des(message, des_key)
    print(f"  - Plaintext: {message}")
    print(f"  - Ciphertext (Base64): {ciphertext_des}")
    
    decrypted_des = decryption.decrypt_des(ciphertext_des, des_key)
    print(f"  - Decrypted: {decrypted_des}")
    assert decrypted_des == message, "DES Decryption should recover the original plaintext."
    print("[DES] DES tests passed.")
    
    # 5. Test RSA Encryption and Decryption
    print("\n[RSA] Testing RSA-2048 PKCS1_OAEP encryption/decryption...")
    short_message = "Target coordinates: 45.109, -122.680"
    ciphertext_rsa = encryption.encrypt_rsa(short_message, pub_pem)
    print(f"  - Plaintext: {short_message}")
    print(f"  - Ciphertext (Base64): {ciphertext_rsa[:60]}...")
    
    decrypted_rsa = decryption.decrypt_rsa(ciphertext_rsa, priv_pem)
    print(f"  - Decrypted: {decrypted_rsa}")
    assert decrypted_rsa == short_message, "RSA Decryption should recover original plaintext."
    print("[RSA] RSA tests passed.")
    
    # 6. Test Error Handling
    print("\n[ERRORS] Testing input validation and exception catching...")
    
    # Test invalid AES key format
    try:
        encryption.encrypt_aes("Hello", "invalid-key")
        assert False, "Should raise ValueError for invalid hex key."
    except ValueError as e:
        print(f"  - Caught expected error (Invalid Hex Key): {e}")
        
    # Test incorrect AES key length
    try:
        encryption.encrypt_aes("Hello", "1234567890abcdef") # 8 bytes instead of 16/24/32
        assert False, "Should raise ValueError for incorrect key size."
    except ValueError as e:
        print(f"  - Caught expected error (Wrong Key Length): {e}")
        
    # Test failed decryption (corrupted key)
    wrong_key = generate_alternative_aes_key(aes_key)
    try:
        decryption.decrypt_aes(ciphertext, wrong_key)
        assert False, "Should raise ValueError for incorrect decryption key."
    except ValueError as e:
        print(f"  - Caught expected error (Decryption Failed): {e}")

    # Test RSA message length limit
    long_msg = "A" * 300 # Exceeds 256 - 42 = 214 bytes capacity
    try:
        encryption.encrypt_rsa(long_msg, pub_pem)
        assert False, "Should raise ValueError for payload exceeding key size capacity."
    except ValueError as e:
        print(f"  - Caught expected error (RSA Payload Limit): {e}")
        
    print("[ERRORS] Error handling tests passed.")
    
    # 7. Final status log review
    all_logs = database.get_history()
    print(f"\n[DB] Final Verification: Total transaction records in database: {len(all_logs)}")
    for log in reversed(all_logs):
        print(f"  ID {log['id']}: {log['operation']} | {log['algorithm']} | Key: {log['key_preview']} | Status: {log['status']}")
        
    print("\n" + "=" * 60)
    print("ALL VERIFICATION TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 60)

def generate_alternative_aes_key(key):
    # Alter the last character to create a wrong key
    last_char = key[-1]
    new_char = '0' if last_char != '0' else '1'
    return key[:-1] + new_char

if __name__ == "__main__":
    run_tests()
