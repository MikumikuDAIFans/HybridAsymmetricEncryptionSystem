from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from user_manager import UserManager
from crypto_utils import HybridEncryptor
import os
import uvicorn
import shutil

app = FastAPI()
security = HTTPBasic()
user_manager = UserManager()

def get_current_user_id(credentials: HTTPBasicCredentials = Depends(security)):
    user_id = user_manager.authenticate(credentials.username, credentials.password)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user_id

@app.post("/upload")
async def upload_file(request: Request, user_id: int = Depends(get_current_user_id)):
    # 1. Plain Upload (Secure Storage Requirement: Cloud stores raw data)
    filename = request.query_params.get("filename", "uploaded_file.bin")
    
    # Secure filename
    filename = os.path.basename(filename)
    output_path = os.path.join("uploads", filename)
    os.makedirs("uploads", exist_ok=True)
    
    # 2. Stream to disk
    try:
        with open(output_path, "wb") as f:
            async for chunk in request.stream():
                f.write(chunk)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    return {"status": "success", "filename": filename, "message": "File stored in plaintext (as per requirements)"}

@app.get("/download")
async def download_file(filename: str, user_id: int = Depends(get_current_user_id)):
    # 1. Check File
    file_path = os.path.join("uploads", os.path.basename(filename))
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    # 2. Get Public Key for User (Server holds Public Key to Encrypt)
    _, pub_pem = user_manager.get_user_keys(user_id)
    if not pub_pem:
        # Fallback to file system key if DB missing (for dev simplicity)
        key_path = "keys/public.pem"
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                pub_pem = f.read()
        else:
            raise HTTPException(status_code=500, detail="User public key not found")
            
    # 3. Encrypt Stream
    if isinstance(pub_pem, str):
        pub_pem = pub_pem.encode()
        
    encryptor = HybridEncryptor(pub_pem)
    
    return StreamingResponse(
        encryptor.encrypt_generator(file_path),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}.enc"}
    )

@app.get("/list")
async def list_files(user_id: int = Depends(get_current_user_id)):
    upload_dir = "uploads"
    if not os.path.exists(upload_dir):
        return []
    files = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))]
    return files

@app.post("/rotate-keys")
async def rotate_keys(user_id: int = Depends(get_current_user_id)):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    # 1. Generate New Key Pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # 2. Serialize Private Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 3. Serialize Public Key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 4. Update Database
    user_manager.update_user_keys(user_id, private_pem, public_pem)
    
    # 5. Return Private Key to User (Securely over HTTPS)
    # The server updates its Public Key record, and gives the Private Key to the user ONE TIME.
    return {
        "status": "success", 
        "message": "Keys rotated successfully. SAVE THIS PRIVATE KEY NOW.",
        "private_key": private_pem.decode()
    }

@app.get("/check-auth")
async def check_auth(user_id: int = Depends(get_current_user_id)):
    return {"status": "authenticated", "user_id": user_id}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
