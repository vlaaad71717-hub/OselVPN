// OselVPN — однофайловый Win32-клиент VPN на ядре Xray (VLESS/REALITY/TLS/WS/gRPC).
// Ядро xray.exe вшито в бинарник как ресурс-блоб и извлекается в %APPDATA%\OselVPN.
#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <cstdio>

#include "vless.h"   // ParseVless + BuildXrayConfig

// Вшитый payload ядра (COFF-объект xray_payload.o)
extern "C" const unsigned char _xray_payload_start[];
extern "C" const unsigned char _xray_payload_end[];

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

#define IDC_LINK        203
#define IDC_CONNECT     201
#define IDC_DISCONNECT  202
#define IDC_STATUS      205
#define IDC_LOG         204
#define WM_APP_LOG      (WM_APP + 1)
#define ID_CHECK_TIMER  2

static const int SOCKS_PORT = 10808;
static const int HTTP_PORT  = 10809;

static HWND g_hwnd, hLink, hConnect, hDisconnect, hStatus, hLog;
static HFONT hFontMain, hFontTitle, hFontLog, hFontSmall;
static HANDLE g_hXrayProc = NULL;
static HANDLE g_hLogThread = NULL;
static HANDLE g_logRead = NULL, g_logWrite = NULL;
static CRITICAL_SECTION g_logCS;
static std::string g_logPending;
static int g_checkCount = 0;
static std::string g_dirA; // %APPDATA%\OselVPN

static void SetStatus(const wchar_t* text) { SetWindowTextW(hStatus, text); }

static std::string AppDir() {
    if (!g_dirA.empty()) return g_dirA;
    std::string dir = "C:\\OselVPN";
    const char* appdata = getenv("APPDATA");
    if (appdata) dir = std::string(appdata) + "\\OselVPN";
    CreateDirectoryA(dir.c_str(), NULL);
    g_dirA = dir;
    return dir;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

// Извлечь ядро из блоба, если его ещё нет (или размер изменился)
static std::string ExtractXray() {
    std::string dst = AppDir() + "\\xray.exe";
    size_t payloadSize = (size_t)(_xray_payload_end - _xray_payload_start);
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (payloadSize > 0 && GetFileAttributesExA(dst.c_str(), GetFileExInfoStandard, &fa)) {
        ULARGE_INTEGER sz; sz.HighPart = fa.nFileSizeHigh; sz.LowPart = fa.nFileSizeLow;
        if (sz.QuadPart == payloadSize) return dst; // уже извлечено
    }
    FILE* f = fopen(dst.c_str(), "wb");
    if (!f) return "";
    fwrite(_xray_payload_start, 1, payloadSize, f);
    fclose(f);
    return dst;
}

static void AppendLogLockedChunk() {
    // вызывается из UI-потока: переносит pending-буфер в контрол
    std::string chunk;
    EnterCriticalSection(&g_logCS);
    chunk.swap(g_logPending);
    LeaveCriticalSection(&g_logCS);
    if (chunk.empty()) return;
    std::wstring w(chunk.begin(), chunk.end()); // лог xray почти весь ascii
    int len = GetWindowTextLengthW(hLog);
    SendMessageW(hLog, EM_SETSEL, len, len);
    SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)w.c_str());
}

static DWORD WINAPI LogThreadProc(LPVOID) {
    char buf[4096];
    DWORD n = 0;
    while (g_logRead && ReadFile(g_logRead, buf, sizeof(buf), &n, NULL) && n > 0) {
        EnterCriticalSection(&g_logCS);
        g_logPending.append(buf, n);
        LeaveCriticalSection(&g_logCS);
        if (g_hwnd) PostMessageW(g_hwnd, WM_APP_LOG, 0, 0);
    }
    return 0;
}

// Системный прокси Windows (WinINET): включить/выключить
static void SetSystemProxy(bool enable) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) return;
    DWORD on = enable ? 1 : 0;
    RegSetValueExA(hKey, "ProxyEnable", 0, REG_DWORD, (const BYTE*)&on, sizeof(on));
    if (enable) {
        const char* server = "127.0.0.1:10809";
        const char* over   = "<local>";
        RegSetValueExA(hKey, "ProxyServer", 0, REG_SZ, (const BYTE*)server, (DWORD)strlen(server) + 1);
        RegSetValueExA(hKey, "ProxyOverride", 0, REG_SZ, (const BYTE*)over, (DWORD)strlen(over) + 1);
    }
    RegCloseKey(hKey);
    InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}

static void StopXray() {
    if (g_hXrayProc) {
        TerminateProcess(g_hXrayProc, 0);
        CloseHandle(g_hXrayProc);
        g_hXrayProc = NULL;
    }
    if (g_logRead) { CloseHandle(g_logRead); g_logRead = NULL; }
    if (g_logWrite) { CloseHandle(g_logWrite); g_logWrite = NULL; }
    SetSystemProxy(false);
}

// Проверка: процесс жив и локальный SOCKS-порт открывается
static bool CheckAlive() {
    if (!g_hXrayProc) return false;
    if (WaitForSingleObject(g_hXrayProc, 0) == WAIT_OBJECT_0) return false;
    WSADATA wsa; // WSAStartup идемпотентен
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(SOCKS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    bool ok = (connect(s, (sockaddr*)&a, sizeof(a)) == 0);
    closesocket(s);
    return ok;
}

static void DoConnect() {
    int len = GetWindowTextLengthW(hLink);
    std::wstring link(len, L'\0');
    GetWindowTextW(hLink, &link[0], len + 1);
    while (!link.empty() && (link.back() == L'\n' || link.back() == L'\r' || link.back() == L' ')) link.pop_back();

    VlessConfig c = ParseVless(link);
    if (!c.ok) {
        SetStatus((L"Ошибка ссылки: " + c.error).c_str());
        MessageBoxW(g_hwnd, c.error.c_str(), L"OselVPN", MB_OK | MB_ICONERROR);
        return;
    }

    SetWindowTextW(hLog, L"");
    // сохранить ссылку
    {
        std::string lf = AppDir() + "\\last_link.txt";
        FILE* f = fopen(lf.c_str(), "wb");
        if (f) { std::string u8 = WideToUtf8(link); fwrite(u8.data(), 1, u8.size(), f); fclose(f); }
    }

    std::string xrayPath = ExtractXray();
    if (xrayPath.empty()) { SetStatus(L"Ошибка: не удалось извлечь xray.exe"); return; }

    std::string cfgPath = AppDir() + "\\config.json";
    {
        std::string cfg = BuildXrayConfig(c, SOCKS_PORT, HTTP_PORT);
        FILE* f = fopen(cfgPath.c_str(), "wb");
        if (!f) { SetStatus(L"Ошибка записи config.json"); return; }
        fwrite(cfg.data(), 1, cfg.size(), f);
        fclose(f);
    }

    // пайп для stderr/stdout ядра
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&g_logRead, &g_logWrite, &sa, 0)) { SetStatus(L"Ошибка CreatePipe"); return; }
    SetHandleInformation(g_logRead, HANDLE_FLAG_INHERIT, 0);

    std::string cmd = "\"" + xrayPath + "\" run -c \"" + cfgPath + "\"";
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = si.hStdError = g_logWrite;
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessA(NULL, &cmd[0], NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, g_dirA.c_str(), &si, &pi);
    CloseHandle(g_logWrite); g_logWrite = NULL; // родителю писать не нужно
    if (!ok) {
        AppendLogLockedChunk();
        SetStatus(L"Ошибка запуска ядра Xray");
        CloseHandle(g_logRead); g_logRead = NULL;
        return;
    }
    CloseHandle(pi.hThread);
    g_hXrayProc = pi.hProcess;
    g_checkCount = 0;
    if (g_logRead) g_hLogThread = CreateThread(NULL, 0, LogThreadProc, NULL, 0, NULL);

    EnableWindow(hConnect, FALSE);
    EnableWindow(hLink, FALSE);
    EnableWindow(hDisconnect, TRUE);
    SetStatus(L"Подключение... (проверяю сервер)");
    SetTimer(g_hwnd, ID_CHECK_TIMER, 1800, NULL);
}

static void OnCheckTimer() {
    KillTimer(g_hwnd, ID_CHECK_TIMER);
    if (!g_hXrayProc) return;
    if (WaitForSingleObject(g_hXrayProc, 0) == WAIT_OBJECT_0) {
        StopXray();
        AppendLogLockedChunk();
        EnableWindow(hConnect, TRUE);
        EnableWindow(hLink, TRUE);
        EnableWindow(hDisconnect, FALSE);
        SetStatus(L"Ошибка: ядро завершилось — проверь ссылку в журнале ниже");
        return;
    }
    if (CheckAlive()) {
        SetSystemProxy(true);
        SetStatus(L"Подключено! Системный прокси: HTTP 127.0.0.1:10809 / SOCKS 127.0.0.1:10808");
        return;
    }
    if (++g_checkCount < 4) {
        SetTimer(g_hwnd, ID_CHECK_TIMER, 1200, NULL);
        return;
    }
    StopXray();
    AppendLogLockedChunk();
    EnableWindow(hConnect, TRUE);
    EnableWindow(hLink, TRUE);
    EnableWindow(hDisconnect, FALSE);
    SetStatus(L"Ошибка: сервер не отвечает (порт закрыт / неверная ссылка)");
}

static void DoDisconnect() {
    KillTimer(g_hwnd, ID_CHECK_TIMER);
    StopXray();
    EnableWindow(hConnect, TRUE);
    EnableWindow(hLink, TRUE);
    EnableWindow(hDisconnect, FALSE);
    SetStatus(L"Отключено. Системный прокси выключен.");
}

static void LoadLastLink() {
    std::string lf = AppDir() + "\\last_link.txt";
    FILE* f = fopen(lf.c_str(), "rb");
    if (!f) return;
    std::string u8;
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) u8.append(buf, n);
    fclose(f);
    std::wstring w = WFromA(u8);
    SetWindowTextW(hLink, w.c_str());
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HFONT f = hFontTitle = CreateFontW(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            hFontMain = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            hFontLog = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Consolas");
            hFontSmall = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");

            HWND t = CreateWindowW(L"STATIC", L"OselVPN", WS_CHILD | WS_VISIBLE | SS_CENTER,
                10, 8, 660, 40, hwnd, NULL, NULL, NULL);
            SendMessage(t, WM_SETFONT, (WPARAM)f, TRUE);
            t = CreateWindowW(L"STATIC", L"Ядро Xray • VLESS / REALITY / TLS / WS / gRPC • режим системного прокси",
                WS_CHILD | WS_VISIBLE | SS_CENTER, 10, 44, 660, 22, hwnd, NULL, NULL, NULL);
            SendMessage(t, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

            t = CreateWindowW(L"STATIC", L"Вставь ссылку VLESS (vless://...):", WS_CHILD | WS_VISIBLE,
                10, 74, 660, 20, hwnd, NULL, NULL, NULL);
            SendMessage(t, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

            hLink = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                10, 96, 660, 26, hwnd, (HMENU)IDC_LINK, NULL, NULL);
            SendMessage(hLink, WM_SETFONT, (WPARAM)hFontMain, TRUE);

            hConnect = CreateWindowW(L"BUTTON", L"Подключить", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 132, 160, 34, hwnd, (HMENU)IDC_CONNECT, NULL, NULL);
            SendMessage(hConnect, WM_SETFONT, (WPARAM)hFontMain, TRUE);
            hDisconnect = CreateWindowW(L"BUTTON", L"Отключить", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                180, 132, 160, 34, hwnd, (HMENU)IDC_DISCONNECT, NULL, NULL);
            SendMessage(hDisconnect, WM_SETFONT, (WPARAM)hFontMain, TRUE);
            EnableWindow(hDisconnect, FALSE);

            hStatus = CreateWindowW(L"STATIC", L"Статус: отключено", WS_CHILD | WS_VISIBLE,
                350, 132, 320, 34, hwnd, (HMENU)IDC_STATUS, NULL, NULL);
            SendMessage(hStatus, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

            hLog = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL |
                ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                10, 178, 660, 200, hwnd, (HMENU)IDC_LOG, NULL, NULL);
            SendMessage(hLog, WM_SETFONT, (WPARAM)hFontLog, TRUE);

            t = CreateWindowW(L"STATIC",
                L"После подключения браузеры пойдут через VPN автоматически. Локальные порты: SOCKS5 10808, HTTP 10809.",
                WS_CHILD | WS_VISIBLE, 10, 386, 660, 20, hwnd, NULL, NULL, NULL);
            SendMessage(t, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

            LoadLastLink();
            break;
        }

        case WM_COMMAND: {
            if (LOWORD(wParam) == IDC_CONNECT && !g_hXrayProc) DoConnect();
            else if (LOWORD(wParam) == IDC_DISCONNECT) DoDisconnect();
            break;
        }

        case WM_TIMER:
            if (wParam == ID_CHECK_TIMER) OnCheckTimer();
            break;

        case WM_APP_LOG:
            AppendLogLockedChunk();
            break;

        case WM_DESTROY:
            KillTimer(g_hwnd, ID_CHECK_TIMER);
            StopXray();
            if (g_hLogThread) { WaitForSingleObject(g_hLogThread, 500); CloseHandle(g_hLogThread); }
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    InitializeCriticalSection(&g_logCS);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"OselVPN";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    g_hwnd = CreateWindowExW(0, L"OselVPN", L"OselVPN",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 460, NULL, NULL, hInstance, NULL);
    ShowWindow(g_hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    WSACleanup();
    return 0;
}
