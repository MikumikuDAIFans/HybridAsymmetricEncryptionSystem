import streamlit as st
import requests
import os
import sys
import tempfile
import subprocess
import shutil

# --- Configuration ---
SERVER_URL = "http://localhost:8000"
USER = "admin"
PASSWORD = "admin123"

# --- Helper: Setup Python Path for Decryption Engine ---
# Add parent directory to path to import decryption_engine from client folder
CLIENT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client")
if CLIENT_DIR not in sys.path:
    sys.path.append(CLIENT_DIR)

try:
    from decryption_engine import HybridDecryptor
except ImportError:
    st.error("Failed to import decryption_engine. Please ensure client/decryption_engine.py exists.")

# --- Session State for Login ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'password' not in st.session_state:
    st.session_state.password = ""
if 'downloaded_files' not in st.session_state:
    st.session_state.downloaded_files = []

# --- Page Config ---
st.set_page_config(page_title="Hybrid Encryption WebUI", layout="wide")
st.title("🛡️ Hybrid Encryption System Manager")

# --- Login System ---
if not st.session_state.logged_in:
    with st.form("login_form"):
        st.header("Login")
        username_input = st.text_input("Username")
        password_input = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")

        if submit_button:
            try:
                # Validate credentials with server
                response = requests.get(
                    f"{SERVER_URL}/check-auth", 
                    auth=(username_input, password_input),
                    timeout=2
                )
                if response.status_code == 200:
                    st.session_state.logged_in = True
                    st.session_state.username = username_input
                    st.session_state.password = password_input
                    st.success("Login Successful!")
                    st.rerun()
                else:
                    st.error("Invalid Username or Password")
            except Exception as e:
                st.error(f"Connection Error: {e}")
    st.stop() # Stop execution if not logged in

# Use credentials from session
USER = st.session_state.username
PASSWORD = st.session_state.password

# --- Sidebar ---
st.sidebar.header(f"Welcome, {USER}")
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.password = ""
    st.rerun()

st.sidebar.divider()
st.sidebar.header("Connection Status")
try:
    # Quick health check (list files)
    response = requests.get(f"{SERVER_URL}/list", auth=(USER, PASSWORD), timeout=2)
    if response.status_code == 200:
        st.sidebar.success("✅ Server Online")
    else:
        st.sidebar.error(f"❌ Server Error: {response.status_code}")
except requests.exceptions.ConnectionError:
    st.sidebar.error("❌ Server Offline")

# --- Tabs ---
tab1, tab2, tab3 = st.tabs(["☁️ Server Module (Cloud)", "💻 Local Module (Client)", "🔑 Key Management"])

# ================= SERVER MODULE =================
with tab1:
    st.header("Server File Management")
    st.info("Files stored in cloud are PLAINTEXT. Downloading triggers real-time ENCRYPTION.")

    # 1. View Files
    st.subheader("1. File List")
    if st.button("Refresh File List"):
        try:
            response = requests.get(f"{SERVER_URL}/list", auth=(USER, PASSWORD))
            if response.status_code == 200:
                files = response.json()
                if files:
                    st.session_state.server_files = files
                else:
                    st.warning("No files found on server.")
            else:
                st.error(f"Failed to fetch file list: {response.text}")
        except Exception as e:
            st.error(f"Error: {e}")
    
    # Display Files
    if 'server_files' in st.session_state and st.session_state.server_files:
        selected_file = st.selectbox("Select file to download:", st.session_state.server_files)
        
        # 2. Download (Encrypted)
        if st.button(f"⬇️ Download & Encrypt '{selected_file}'"):
            with st.spinner("Downloading encrypted stream..."):
                try:
                    url = f"{SERVER_URL}/download"
                    response = requests.get(
                        url,
                        params={"filename": selected_file},
                        auth=(USER, PASSWORD),
                        stream=True
                    )
                    
                    if response.status_code == 200:
                        # Save to a local temporary download folder
                        downloads_dir = os.path.join(os.path.dirname(__file__), "downloads")
                        os.makedirs(downloads_dir, exist_ok=True)
                        enc_filename = f"{selected_file}.enc"
                        save_path = os.path.join(downloads_dir, enc_filename)
                        
                        with open(save_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)
                                
                        st.success(f"Encrypted file downloaded to: {save_path}")
                        st.session_state.downloaded_files.append(save_path)
                    else:
                        st.error(f"Download failed: {response.status_code} - {response.text}")
                except Exception as e:
                    st.error(f"Download Error: {e}")

# ================= LOCAL MODULE =================
with tab2:
    st.header("Local Operations")
    
    col1, col2 = st.columns(2)
    
    # 1. Decrypt Function
    with col1:
        st.subheader("🔓 Decrypt File")
        st.info("Decrypts .enc files using local Private Key.")
        
        # Scan for .enc files in downloads folder
        downloads_dir = os.path.join(os.path.dirname(__file__), "downloads")
        os.makedirs(downloads_dir, exist_ok=True)
        enc_files = [f for f in os.listdir(downloads_dir) if f.endswith(".enc")]
        
        target_enc = st.selectbox("Select encrypted file:", enc_files)
        
        if target_enc and st.button("Decrypt Selected File"):
            enc_path = os.path.join(downloads_dir, target_enc)
            # Remove .enc extension
            out_filename = target_enc[:-4] if target_enc.endswith(".enc") else f"dec_{target_enc}"
            out_path = os.path.join(downloads_dir, out_filename)
            
            # Load Private Key
            priv_key_path = os.path.join(CLIENT_DIR, "resources", "private.pem")
            
            if not os.path.exists(priv_key_path):
                st.error(f"Private Key not found at {priv_key_path}!")
            else:
                try:
                    with open(priv_key_path, "rb") as f:
                        priv_key_pem = f.read()
                    
                    decryptor = HybridDecryptor(priv_key_pem)
                    
                    # Decrypt
                    with st.spinner("Decrypting..."):
                        # We need to simulate a stream from the file for the engine
                        def file_stream_gen(path):
                            with open(path, "rb") as f:
                                while True:
                                    chunk = f.read(65536)
                                    if not chunk: break
                                    yield chunk
                        
                        decryptor.decrypt_stream_to_file(file_stream_gen(enc_path), out_path)
                    
                    st.success(f"Decryption Successful! Saved to: {out_path}")
                    
                    # Open in Explorer
                    if st.button("📂 Open File Location"):
                        # Fix path for Windows command line (backslashes)
                        abs_path = os.path.abspath(out_path).replace("/", "\\")
                        cmd = f'explorer /select,"{abs_path}"'
                        subprocess.Popen(cmd)
                        
                except Exception as e:
                    st.error(f"Decryption Failed: {e}")

    # 2. Upload Function
    with col2:
        st.subheader("⬆️ Upload File")
        st.info("Uploads PLAINTEXT to Cloud (Secure Channel).")
        
        uploaded_file = st.file_uploader("Choose a file")
        
        if uploaded_file is not None:
            if st.button("Upload to Server"):
                with st.spinner("Uploading..."):
                    try:
                        files = {'file': (uploaded_file.name, uploaded_file, "application/octet-stream")}
                        # We need to send data as body, not multipart for our specific server implementation
                        # Our server expects raw body stream
                        
                        # Reset pointer
                        uploaded_file.seek(0)
                        
                        response = requests.post(
                            f"{SERVER_URL}/upload",
                            params={"filename": uploaded_file.name},
                            data=uploaded_file,
                            auth=(USER, PASSWORD)
                        )
                        
                        if response.status_code == 200:
                            st.success(f"Upload Success: {uploaded_file.name}")
                        else:
                            st.error(f"Upload Failed: {response.text}")
                    except Exception as e:
                        st.error(f"Upload Error: {e}")

# ================= KEY MANAGEMENT MODULE =================
with tab3:
    st.header("Key Management")
    st.warning("⚠️ Rotating keys will generate a NEW Private Key. You MUST save it, otherwise you cannot decrypt new files.")
    
    if st.button("🔄 Rotate Key Pair (Generate New Keys)"):
        with st.spinner("Requesting new keys from server..."):
            try:
                response = requests.post(
                    f"{SERVER_URL}/rotate-keys",
                    auth=(USER, PASSWORD)
                )
                
                if response.status_code == 200:
                    data = response.json()
                    new_private_key = data.get("private_key")
                    
                    if new_private_key:
                        # Update Local Key
                        priv_key_path = os.path.join(CLIENT_DIR, "resources", "private.pem")
                        
                        # Backup old key
                        if os.path.exists(priv_key_path):
                            backup_path = f"{priv_key_path}.bak"
                            shutil.copy(priv_key_path, backup_path)
                            st.info(f"Old private key backed up to: {backup_path}")
                        
                        # Write new key
                        with open(priv_key_path, "w") as f:
                            f.write(new_private_key)
                            
                        st.success("✅ Keys Rotated Successfully!")
                        st.success(f"New Private Key saved to: {priv_key_path}")
                        st.balloons()
                    else:
                        st.error("Server did not return a private key.")
                else:
                    st.error(f"Rotation Failed: {response.text}")
            except Exception as e:
                st.error(f"Connection Error: {e}")
