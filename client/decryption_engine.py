import struct
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

MAGIC = b"HENC"

class DecryptionError(Exception):
    pass

class HybridDecryptor:
    def __init__(self, private_key_pem):
        self.private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

    def decrypt_stream_to_file(self, response_stream, output_file_path):
        # We need a generator that yields bytes from the response stream
        generator = response_stream
        
        # Buffer for reading headers
        buffer = bytearray()
        
        # Helper to pull N bytes from generator
        def read_exact(n):
            nonlocal buffer
            while len(buffer) < n:
                try:
                    chunk = next(generator)
                    buffer.extend(chunk)
                except StopIteration:
                     raise DecryptionError("Unexpected End of Stream during header read")
            data = buffer[:n]
            del buffer[:n]
            return data

        # 1. Read Magic
        magic = read_exact(4)
        if magic != MAGIC:
            raise DecryptionError("Invalid Magic Signature")

        # 2. Read Ver & Algo
        ver = read_exact(1)[0]
        algo = read_exact(1)[0]
        
        if ver != 1:
            raise DecryptionError(f"Unsupported Protocol Version: {ver}")
        if algo != 1: # AES-GCM
            raise DecryptionError(f"Unsupported Algorithm: {algo}")

        # 3. Read Block Size
        bs_bytes = read_exact(4)
        block_size = struct.unpack(">I", bs_bytes)[0]

        # 4. Read Base IV
        base_iv = read_exact(12)

        # 5. Read Enc DEK Len
        dek_len_bytes = read_exact(2)
        dek_len = struct.unpack(">H", dek_len_bytes)[0]

        # 6. Read Enc DEK
        enc_dek = read_exact(dek_len)

        # Decrypt DEK
        try:
            dek = self.private_key.decrypt(
                bytes(enc_dek),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise DecryptionError("Failed to decrypt DEK") from e

        # Process Body
        chunk_idx = 0
        full_chunk_size = block_size + 16
        
        os.makedirs(os.path.dirname(os.path.abspath(output_file_path)) or '.', exist_ok=True)
        
        with open(output_file_path, "wb") as out_f:
            while True:
                # Read full chunk (Ciphertext + Tag)
                # We need to be careful with the buffer logic for the body
                while len(buffer) < full_chunk_size:
                    try:
                        chunk = next(generator)
                        if not chunk: break
                        buffer.extend(chunk)
                    except StopIteration:
                        break
                
                if len(buffer) == 0:
                    break
                    
                # If we have partial data at the end (less than tag size), it's an error
                # But valid last block can be smaller than full_chunk_size
                # However, it MUST have at least 16 bytes for tag
                if len(buffer) < 16:
                     raise DecryptionError("Data too short for Tag")
                
                # Determine current chunk size (could be smaller than block_size + 16 for last block)
                # But we must consume up to full_chunk_size if available
                take_len = min(len(buffer), full_chunk_size)
                current_chunk_data = buffer[:take_len]
                del buffer[:take_len]
                
                tag = bytes(current_chunk_data[-16:])
                ciphertext = bytes(current_chunk_data[:-16])
                
                # Derive Nonce: Base IV XOR (chunk_idx << 32)
                base_iv_int = int.from_bytes(base_iv, 'big')
                nonce_int = base_iv_int ^ (chunk_idx << 32)
                nonce = nonce_int.to_bytes(12, 'big')
                
                # Decrypt
                cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce, tag, min_tag_length=16), backend=default_backend())
                decryptor = cipher.decryptor()
                try:
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    out_f.write(plaintext)
                except Exception as e:
                    # Security: Delete partial file on error
                    out_f.close()
                    if os.path.exists(output_file_path):
                        os.remove(output_file_path)
                    raise DecryptionError(f"Auth Tag Validation Failed at chunk {chunk_idx}") from e
                
                chunk_idx += 1
