import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

class UserManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def authenticate(self, username, password):
        """Returns user_id if successful, None otherwise."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?", (username, pw_hash))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result[0]
        return None

    def get_user_keys(self, user_id):
        """Returns (private_key_pem, public_key_pem) for the user."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT private_key, public_key FROM user_keys WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result[0], result[1]
        return None, None

    def update_user_keys(self, user_id, private_pem, public_pem):
        """Updates the keys for a specific user."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if keys exist
        cursor.execute("SELECT id FROM user_keys WHERE user_id = ?", (user_id,))
        if cursor.fetchone():
            cursor.execute("UPDATE user_keys SET private_key = ?, public_key = ? WHERE user_id = ?", 
                           (private_pem, public_pem, user_id))
        else:
            cursor.execute("INSERT INTO user_keys (user_id, private_key, public_key) VALUES (?, ?, ?)",
                           (user_id, private_pem, public_pem))
            
        conn.commit()
        conn.close()
        return True
