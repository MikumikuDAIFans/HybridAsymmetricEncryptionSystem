import struct
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

MAGIC = b"HENC"
VERSION = 1
ALGO_AES_GCM = 1
BLOCK_SIZE = 65536 # 64KB

class DecryptionError(Exception):
    pass

class HybridEncryptor:
    def __init__(self, public_key_pem):
        self.public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

    def encrypt_generator(self, file_path):
        # 1. Init Session Key (DEK) & Base IV
        dek = os.urandom(32) # AES-256
        base_iv = os.urandom(12) # 96-bit
        
        # 2. Encrypt DEK with RSA
        enc_dek = self.public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Yield Header
        # Magic (4) + Ver (1) + Algo (1) + BlockSize (4) + BaseIV (12) + EncDEKLen (2) + EncDEK
        header = bytearray()
        header.extend(MAGIC)
        header.append(VERSION)
        header.append(ALGO_AES_GCM)
        header.extend(struct.pack(">I", BLOCK_SIZE))
        header.extend(base_iv)
        header.extend(struct.pack(">H", len(enc_dek)))
        header.extend(enc_dek)
        
        yield bytes(header)
        
        # 4. Stream Body
        chunk_idx = 0
        
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(BLOCK_SIZE)
                if not chunk:
                    break
                
                # Derive Nonce
                base_iv_int = int.from_bytes(base_iv, 'big')
                nonce_int = base_iv_int ^ (chunk_idx << 32)
                nonce = nonce_int.to_bytes(12, 'big')
                
                # Encrypt Chunk
                cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                
                ciphertext = encryptor.update(chunk) + encryptor.finalize()
                tag = encryptor.tag
                
                yield ciphertext + tag
                
                chunk_idx += 1
