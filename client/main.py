import sys
import os
import requests
import argparse
from decryption_engine import HybridDecryptor

# Resource path helper for PyInstaller
def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def upload(args):
    url = f"{args.url}/upload"
    print(f"Uploading {args.file} to {url} (Plaintext)...")
    
    with open(args.file, "rb") as f:
        try:
            response = requests.post(
                url,
                params={"filename": os.path.basename(args.file)},
                data=f, # Stream upload
                auth=(args.user, args.password)
            )
            
            if response.status_code == 200:
                print("Upload Success!")
                print(response.json())
            else:
                print(f"Upload Failed: {response.status_code}")
                print(response.text)
        except Exception as e:
             print(f"Error: {e}")

def download(args):
    url = f"{args.url}/download"
    print(f"Downloading {args.file} from {url} (Encrypted Stream)...")
    
    # Load Private Key (Client holds Private Key)
    priv_key_path = os.path.join(os.path.dirname(__file__), "resources", "private.pem")
    if not os.path.exists(priv_key_path):
        priv_key_path = get_resource_path("private.pem")
        
    if not os.path.exists(priv_key_path):
        print(f"Error: private.pem not found at {priv_key_path}.")
        sys.exit(1)
        
    with open(priv_key_path, "rb") as f:
        priv_key_pem = f.read()
        
    decryptor = HybridDecryptor(priv_key_pem)
    
    try:
        # Request stream
        response = requests.get(
            url,
            params={"filename": args.file},
            auth=(args.user, args.password),
            stream=True
        )
        
        if response.status_code != 200:
            print(f"Download Failed: {response.status_code}")
            print(response.text)
            return

        # Output filename
        output_filename = f"downloaded_{args.file}"
        
        # Process Stream through Decryptor
        decryptor.decrypt_stream_to_file(response.iter_content(chunk_size=65552), output_filename)
        
        print(f"Download & Decryption Success! Saved to {output_filename}")
            
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Hybrid Secure Distribution Client")
    parser.add_argument("--url", default="http://localhost:8000", help="Server URL base")
    parser.add_argument("--user", default="admin", help="Username")
    parser.add_argument("--pass", dest="password", default="admin123", help="Password")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Upload Command
    upload_parser = subparsers.add_parser("upload", help="Upload plaintext file")
    upload_parser.add_argument("file", help="File to upload")
    
    # Download Command
    download_parser = subparsers.add_parser("download", help="Download and decrypt file")
    download_parser.add_argument("file", help="Filename on server to download")
    
    args = parser.parse_args()
    
    if args.command == "upload":
        upload(args)
    elif args.command == "download":
        download(args)

if __name__ == "__main__":
    main()
