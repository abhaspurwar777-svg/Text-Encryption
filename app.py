from flask import Flask, request, jsonify, send_from_directory
import os
import traceback

import key_management
import encryption
import decryption
import database

app = Flask(__name__, static_folder="static", static_url_path="")

# Initialize the database on startup
database.init_db()

@app.route("/")
def serve_index():
    """Serves the main frontend dashboard index.html page."""
    return app.send_static_file("index.html")

@app.route("/api/generate-key", methods=["POST"])
def api_generate_key():
    """
    POST endpoint to generate cryptographic keys.
    Expects JSON: { "algorithm": "AES" | "DES" | "RSA" }
    """
    data = request.get_json() or {}
    algo = data.get("algorithm", "").upper()
    
    try:
        if algo == "AES":
            key = key_management.generate_aes_key()
            return jsonify({"status": "success", "key": key})
        elif algo == "DES":
            key = key_management.generate_des_key()
            return jsonify({"status": "success", "key": key})
        elif algo == "RSA":
            pub_key, priv_key = key_management.generate_rsa_keypair()
            return jsonify({
                "status": "success",
                "public_key": pub_key,
                "private_key": priv_key
            })
        else:
            return jsonify({"status": "error", "message": "Unsupported algorithm. Use AES, DES, or RSA."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Key generation failed: {str(e)}"}), 500

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """
    POST endpoint to encrypt text.
    Expects JSON: { "text": "...", "algorithm": "AES"|"DES"|"RSA", "key": "..." }
    If key is empty, it will be automatically generated.
    """
    data = request.get_json() or {}
    plaintext = data.get("text", "")
    algorithm = data.get("algorithm", "").upper()
    key = data.get("key", "").strip()
    
    if not plaintext:
        return jsonify({"status": "error", "message": "Plaintext cannot be empty."}), 400
    if algorithm not in ["AES", "DES", "RSA"]:
        return jsonify({"status": "error", "message": "Unsupported algorithm. Use AES, DES, or RSA."}), 400

    generated_key_info = {}
    key_preview = ""
    ciphertext = ""
    
    try:
        if algorithm == "AES":
            # Auto-generate key if not provided
            if not key:
                key = key_management.generate_aes_key()
                generated_key_info["key"] = key
                generated_key_info["note"] = "AES key generated automatically."
            
            key_preview = f"AES-256 ({key[:8]}...)"
            ciphertext = encryption.encrypt_aes(plaintext, key)
            
        elif algorithm == "DES":
            # Auto-generate key if not provided
            if not key:
                key = key_management.generate_des_key()
                generated_key_info["key"] = key
                generated_key_info["note"] = "DES key generated automatically."
            
            key_preview = f"DES-64 ({key[:8]}...)"
            ciphertext = encryption.encrypt_des(plaintext, key)
            
        elif algorithm == "RSA":
            # Auto-generate keys if public key is not provided
            if not key:
                pub_key, priv_key = key_management.generate_rsa_keypair()
                key = pub_key
                generated_key_info["public_key"] = pub_key
                generated_key_info["private_key"] = priv_key
                generated_key_info["note"] = "RSA public/private keys generated automatically."
            
            key_preview = "RSA-2048 (Public)"
            ciphertext = encryption.encrypt_rsa(plaintext, key)
            
        # Log to database
        database.add_history_log(
            algorithm=algorithm,
            operation="ENCRYPT",
            input_length=len(plaintext),
            key_preview=key_preview,
            status="SUCCESS"
        )
        
        response = {
            "status": "success",
            "ciphertext": ciphertext,
            "algorithm": algorithm
        }
        # Include any newly generated keys in the response
        if generated_key_info:
            response["generated_keys"] = generated_key_info
            
        return jsonify(response)
        
    except Exception as e:
        # Construct error logs
        err_msg = str(e)
        # Fallback key preview if key was corrupted/empty
        if not key_preview:
            key_preview = "Invalid/Empty Key"
            
        database.add_history_log(
            algorithm=algorithm,
            operation="ENCRYPT",
            input_length=len(plaintext),
            key_preview=key_preview,
            status="FAILURE",
            error_message=err_msg
        )
        return jsonify({"status": "error", "message": err_msg}), 400

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """
    POST endpoint to decrypt text.
    Expects JSON: { "ciphertext": "...", "algorithm": "AES"|"DES"|"RSA", "key": "..." }
    The key is mandatory for decryption.
    """
    data = request.get_json() or {}
    ciphertext = data.get("ciphertext", "").strip()
    algorithm = data.get("algorithm", "").upper()
    key = data.get("key", "").strip()
    
    if not ciphertext:
        return jsonify({"status": "error", "message": "Ciphertext cannot be empty."}), 400
    if not key:
        return jsonify({"status": "error", "message": "Key/Private Key is required for decryption."}), 400
    if algorithm not in ["AES", "DES", "RSA"]:
        return jsonify({"status": "error", "message": "Unsupported algorithm. Use AES, DES, or RSA."}), 400

    key_preview = ""
    try:
        if algorithm == "AES":
            key_preview = f"AES-256 ({key[:8]}...)"
            plaintext = decryption.decrypt_aes(ciphertext, key)
        elif algorithm == "DES":
            key_preview = f"DES-64 ({key[:8]}...)"
            plaintext = decryption.decrypt_des(ciphertext, key)
        elif algorithm == "RSA":
            key_preview = "RSA-2048 (Private)"
            plaintext = decryption.decrypt_rsa(ciphertext, key)
            
        # Log to database
        database.add_history_log(
            algorithm=algorithm,
            operation="DECRYPT",
            input_length=len(ciphertext),
            key_preview=key_preview,
            status="SUCCESS"
        )
        
        return jsonify({
            "status": "success",
            "plaintext": plaintext,
            "algorithm": algorithm
        })
        
    except Exception as e:
        err_msg = str(e)
        if not key_preview:
            key_preview = f"{algorithm} Key"
            
        database.add_history_log(
            algorithm=algorithm,
            operation="DECRYPT",
            input_length=len(ciphertext),
            key_preview=key_preview,
            status="FAILURE",
            error_message=err_msg
        )
        return jsonify({"status": "error", "message": err_msg}), 400

@app.route("/api/history", methods=["GET"])
def api_get_history():
    """GET endpoint to fetch operation logs."""
    try:
        logs = database.get_history()
        return jsonify({"status": "success", "history": logs})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """POST endpoint to clear all operation logs."""
    try:
        database.clear_history()
        return jsonify({"status": "success", "message": "Transaction logs successfully cleared."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    # Use self‑signed certificate for local HTTPS.
    # Place `cert.pem` and `key.pem` in the project root.
    # If they do not exist, the server will fall back to HTTP.
    cert_path = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_path = os.path.join(os.path.dirname(__file__), "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        app.run(host="127.0.0.1", port=5000, debug=True, ssl_context=(cert_path, key_path))
    else:
        print("[INFO] SSL certificate not found, starting HTTP server.")
        app.run(host="127.0.0.1", port=5000, debug=True)
