import os
import sqlite3
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Configuration
SERVER_KEYS_DIR = "server/app/keys"
CLIENT_RESOURCES_DIR = "client/resources"
DB_PATH = "server/app/users.db"

def ensure_dirs():
    os.makedirs(SERVER_KEYS_DIR, exist_ok=True)
    os.makedirs(CLIENT_RESOURCES_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def generate_keys():
    print("Generating RSA-4096 Key Pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Serialize Private Key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize Public Key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write to files - SWAPPED for "Secure Download" architecture
    # Server gets Public Key (to encrypt downloads)
    with open(os.path.join(SERVER_KEYS_DIR, "public.pem"), "wb") as f:
        f.write(pem_public)
    
    # Client gets Private Key (to decrypt downloads)
    with open(os.path.join(CLIENT_RESOURCES_DIR, "private.pem"), "wb") as f:
        f.write(pem_private)
        
    print(f"Keys saved: Server->Public, Client->Private")
    return pem_private, pem_public

def init_db(pem_private, pem_public):
    print("Initializing User Database (SQLite)...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create Keys Table
    # NOTE: In this architecture, the server technically only needs the Public Key.
    # But we store both in DB for record keeping, though the file system deployment is strictly separated.
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        public_key TEXT,
        private_key TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    
    # Add Default Admin User
    # Simple hash for demo purposes (SHA256 of 'admin123')
    pw_hash = hashlib.sha256(b"admin123").hexdigest()
    
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ('admin', pw_hash))
        user_id = cursor.lastrowid
        print("Default user 'admin' created.")
        
        # Store keys for this user
        cursor.execute("INSERT INTO user_keys (user_id, public_key, private_key) VALUES (?, ?, ?)", 
                       (user_id, pem_public.decode('utf-8'), pem_private.decode('utf-8')))
        print("Keys associated with user 'admin'.")
        
    except sqlite3.IntegrityError:
        print("User 'admin' already exists.")
        
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")

if __name__ == "__main__":
    ensure_dirs()
    priv, pub = generate_keys()
    init_db(priv, pub)
