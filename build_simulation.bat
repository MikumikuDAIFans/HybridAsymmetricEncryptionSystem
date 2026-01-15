@echo off
echo ==========================================
echo Hybrid Encryption System Simulation Setup
echo ==========================================

echo [1/5] Checking Environment...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Docker is not installed or not in PATH.
    echo Please install Docker Desktop for Windows.
    echo Skipping Docker check for now assuming dev env...
)
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)

echo [2/5] Installing Client Dependencies...
pip install -r client/requirements.txt

echo [3/5] Building Client Executable...
cd client
pyinstaller client.spec
cd ..
if not exist "client\dist\HybridClient.exe" (
    echo Error: Client build failed.
    pause
    exit /b 1
)
echo Client built successfully at client\dist\HybridClient.exe

echo [4/5] Building Server Docker Image...
echo This may take a while...
docker build -t hybrid-enc-server ./server

echo [5/5] Starting Server Container...
docker stop hybrid-sim-instance >nul 2>&1
docker rm hybrid-sim-instance >nul 2>&1
docker run -d -p 8000:8000 --name hybrid-sim-instance hybrid-enc-server

echo ==========================================
echo Simulation Environment Ready!
echo Server running at http://localhost:8000
echo Client located at client\dist\HybridClient.exe
echo.
echo Test Command:
echo 1. Upload (Plaintext): client\dist\HybridClient.exe upload <path_to_file> --user admin --pass admin123
echo 2. Download (Encrypted): client\dist\HybridClient.exe download <filename> --user admin --pass admin123
echo ==========================================
pause
