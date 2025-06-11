# 🕶️ ShadowStream

**ShadowStream** is a stealthy screen streaming tool that captures the victim’s desktop silently and transmits it over HTTP as a series of image frames. Designed for red team operations and post-exploitation scenarios, ShadowStream is built for stealth, speed, and simplicity.

---

## ⚙️ Features

- 🔒 **Hidden Execution**: Runs silently in the background without any visible windows or user prompts.  
- 🌐 **HTTP Frame Streaming**: Streams desktop screenshots over plain HTTP using discreet request-based exfiltration.  
- 📸 **Real-Time Visual Feed**: Continuously captures screen snapshots with minimal delay between frames.  
- 🎯 **Lightweight Architecture**: Minimal overhead, ideal for integration with C2 panels or use in restricted environments.  
- 🧰 **Modular Design**: Easy to modify or extend for additional capabilities such as compression or encryption.  
- 🔄 **Persistence**: Startup apps Persistence to Ensure ShadowStream runs automatically on system startup.

---

## 🚀 Usage

### Running the Server

Start the server by running:

```bash
python3 server.py

