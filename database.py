import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securetext.db")

def get_connection():
    """
    Establishes and returns a connection to the SQLite database.
    Enables dictionary-like row access.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database schema if it doesn't already exist.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encryption_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            algorithm TEXT NOT NULL,
            operation TEXT NOT NULL,
            input_length INTEGER NOT NULL,
            key_preview TEXT NOT NULL,
            status TEXT NOT NULL,
            error_message TEXT
        )
    """)
    conn.commit()
    conn.close()

def add_history_log(algorithm: str, operation: str, input_length: int, key_preview: str, status: str, error_message: str = None):
    """
    Logs an encryption or decryption transaction into the database.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO encryption_history (algorithm, operation, input_length, key_preview, status, error_message)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (algorithm, operation, input_length, key_preview, status, error_message))
    conn.commit()
    conn.close()

def get_history(limit: int = 50) -> list[dict]:
    """
    Retrieves recent transaction logs from the database.
    Returns:
        list of dicts containing log rows.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, algorithm, operation, input_length, key_preview, status, error_message
        FROM encryption_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    
    history_list = []
    for row in rows:
        history_list.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "algorithm": row["algorithm"],
            "operation": row["operation"],
            "input_length": row["input_length"],
            "key_preview": row["key_preview"],
            "status": row["status"],
            "error_message": row["error_message"]
        })
    conn.close()
    return history_list

def clear_history():
    """
    Clears all transaction logs from the database.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM encryption_history")
    conn.commit()
    conn.close()
