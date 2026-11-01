// vless.h — парсер ссылки vless:// и генератор config.json для Xray-core.
// Чистый C++ (STL only) — используется и в OselVPN.exe, и в линукс-тесте.
#pragma once
#include <string>
#include <vector>
#include <cctype>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#endif

struct VlessConfig {
    bool ok = false;
    std::wstring error;
    // поля ссылки
    std::wstring raw, name, uuid, host, port;
    std::wstring security;   // none | tls | reality
    std::wstring network;    // tcp | ws | grpc | ...
    std::wstring sni, fp, pbk, sid, spiderX;
    std::wstring path, hostHeader, serviceName, alpn, flow;
};

// UTF-8 bytes -> wide. Windows: настоящая конвертация (кириллица в имени/пути).
// Linux-тест: побайтово (для отладки).
static std::wstring WFromA(const std::string& s) {
#ifdef _WIN32
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
#else
    return std::wstring(s.begin(), s.end());
#endif
}

// %-декодирование URL (utf-8 -> wide по байтам, как делает v2rayN)
static std::wstring UrlDecode(const std::wstring& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); i++) {
        wchar_t c = in[i];
        if (c == L'%' && i + 2 < in.size() + 1 && isxdigit((int)in[i+1]) && isxdigit((int)in[i+2])) {
            auto hexv = [](wchar_t h)->int {
                if (h >= L'0' && h <= L'9') return h - L'0';
                if (h >= L'a' && h <= L'f') return h - L'a' + 10;
                if (h >= L'A' && h <= L'F') return h - L'A' + 10;
                return 0;
            };
            out.push_back((char)((hexv(in[i+1]) << 4) | hexv(in[i+2])));
            i += 2;
        } else {
            out.push_back((char)(unsigned char)c);
        }
    }
    return WFromA(out);
}

// экранирование wchar-строки для JSON с кодированием не-ASCII в UTF-8:
// работает и когда wchar_t несёт реальные codepoints (Windows),
// и когда побайтово расширенные UTF-8 байты (линукс-тест)
static void Utf8AppendCodepoint(std::string& s, unsigned int cp) {
    if (cp < 0x80) s += (char)cp;
    else if (cp < 0x800) {
        s += (char)(0xC0 | (cp >> 6));
        s += (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        s += (char)(0xE0 | (cp >> 12));
        s += (char)(0x80 | ((cp >> 6) & 0x3F));
        s += (char)(0x80 | (cp & 0x3F));
    } else {
        s += (char)(0xF0 | (cp >> 18));
        s += (char)(0x80 | ((cp >> 12) & 0x3F));
        s += (char)(0x80 | ((cp >> 6) & 0x3F));
        s += (char)(0x80 | (cp & 0x3F));
    }
}

static std::string JsonEsc(const std::wstring& w) {
    std::string s;
    for (wchar_t wc : w) {
        unsigned int cp = (unsigned int)wc;
        switch (wc) {
            case L'"':  s += "\\\""; break;
            case L'\\': s += "\\\\"; break;
            case L'\n': s += "\\n";  break;
            case L'\r': s += "\\r";  break;
            case L'\t': s += "\\t";  break;
            default:
                if (cp < 0x20) {
                    char buf[8]; snprintf(buf, sizeof(buf), "\\u%04x", cp); s += buf;
                } else {
                    Utf8AppendCodepoint(s, cp);
                }
        }
    }
    return s;
}

// Разбор ссылки vless://uuid@host:port?params#name
static VlessConfig ParseVless(const std::wstring& link) {
    VlessConfig c;
    c.raw = link;
    std::wstring body = link;
    if (body.rfind(L"vless://", 0) == 0) body = body.substr(8);
    else if (body.rfind(L"VLESS://", 0) == 0) body = body.substr(8);
    else { c.error = L"Ссылка должна начинаться с vless://"; return c; }

    // фрагмент (название)
    size_t hash = body.find(L'#');
    if (hash != std::wstring::npos) {
        c.name = UrlDecode(body.substr(hash + 1));
        body = body.substr(0, hash);
    }
    // параметры
    std::wstring params;
    size_t q = body.find(L'?');
    if (q != std::wstring::npos) {
        params = body.substr(q + 1);
        body = body.substr(0, q);
    }
    // uuid@host:port
    size_t at = body.rfind(L'@');
    if (at == std::wstring::npos) { c.error = L"В ссылке нет UUID (@uuid@host)"; return c; }
    c.uuid = body.substr(0, at);
    std::wstring hostport = body.substr(at + 1);
    if (!hostport.empty() && hostport[0] == L'[') { // IPv6
        size_t cb = hostport.find(L']');
        if (cb == std::wstring::npos) { c.error = L"Некорректный IPv6-адрес"; return c; }
        c.host = hostport.substr(1, cb - 1);
        size_t colon = hostport.find(L':', cb);
        c.port = (colon != std::wstring::npos) ? hostport.substr(colon + 1) : L"443";
    } else {
        size_t colon = hostport.rfind(L':');
        if (colon == std::wstring::npos) { c.host = hostport; c.port = L"443"; }
        else { c.host = hostport.substr(0, colon); c.port = hostport.substr(colon + 1); }
    }
    if (c.uuid.empty() || c.host.empty()) { c.error = L"Пустой UUID или адрес сервера"; return c; }
    if (c.port.empty()) c.port = L"443";

    // query-параметры
    auto getParam = [&](const std::wstring& key)->std::wstring {
        size_t pos = 0;
        while (pos <= params.size()) {
            size_t amp = params.find(L'&', pos);
            std::wstring kv = params.substr(pos, (amp == std::wstring::npos) ? std::wstring::npos : amp - pos);
            size_t eq = kv.find(L'=');
            if (eq != std::wstring::npos && kv.substr(0, eq) == key)
                return UrlDecode(kv.substr(eq + 1));
            if (amp == std::wstring::npos) break;
            pos = amp + 1;
        }
        return L"";
    };
    c.security    = getParam(L"security");
    c.network     = getParam(L"type");
    c.sni         = getParam(L"sni");
    c.fp          = getParam(L"fp");
    c.pbk         = getParam(L"pbk");
    c.sid         = getParam(L"sid");
    c.spiderX     = getParam(L"spiderX");
    c.path        = getParam(L"path");
    c.hostHeader  = getParam(L"host");
    c.serviceName = getParam(L"serviceName");
    c.alpn        = getParam(L"alpn");
    c.flow        = getParam(L"flow");

    if (c.security.empty()) c.security = (c.pbk.empty() ? L"tls" : L"reality");
    if (c.network.empty())  c.network = L"tcp";
    if (c.security == L"reality" && c.pbk.empty()) { c.error = L"REALITY без параметра pbk (publicKey) не работает"; return c; }
    // flow имеет смысл только для tcp+tls/reality
    if (c.network != L"tcp") c.flow.clear();

    c.ok = true;
    return c;
}

// Генерация config.json для xray-core.
// socksPort/httpPort — локальные порты входящих подключений.
static std::string BuildXrayConfig(const VlessConfig& c, int socksPort, int httpPort) {
    std::string j = "{\n";
    j += "  \"log\": {\"loglevel\": \"warning\"},\n";
    j += "  \"inbounds\": [\n";
    j += "    {\"tag\": \"socks-in\", \"listen\": \"127.0.0.1\", \"port\": " + std::to_string(socksPort) +
         ", \"protocol\": \"socks\", \"settings\": {\"auth\": \"noauth\", \"udp\": true}},\n";
    j += "    {\"tag\": \"http-in\", \"listen\": \"127.0.0.1\", \"port\": " + std::to_string(httpPort) +
         ", \"protocol\": \"http\", \"settings\": {}}\n";
    j += "  ],\n";
    j += "  \"outbounds\": [\n";
    j += "    {\n";
    j += "      \"tag\": \"proxy\",\n";
    j += "      \"protocol\": \"vless\",\n";
    j += "      \"settings\": {\n";
    j += "        \"vnext\": [{\n";
    j += "          \"address\": \"" + JsonEsc(c.host) + "\",\n";
    j += "          \"port\": " + std::string(JsonEsc(c.port)) + ",\n";
    j += "          \"users\": [{\n";
    j += "            \"id\": \"" + JsonEsc(c.uuid) + "\",\n";
    j += "            \"encryption\": \"none\",\n";
    j += "            \"level\": 0";
    if (!c.flow.empty()) j += ",\n            \"flow\": \"" + JsonEsc(c.flow) + "\"";
    j += "\n          }]\n";
    j += "        }]\n";
    j += "      },\n";
    j += "      \"streamSettings\": {\n";
    j += "        \"network\": \"" + JsonEsc(c.network) + "\",\n";
    j += "        \"security\": \"" + JsonEsc(c.security) + "\",\n";
    if (c.security == L"tls") {
        j += "        \"tlsSettings\": {\n";
        j += "          \"serverName\": \"" + JsonEsc(c.sni.empty() ? c.host : c.sni) + "\",\n";
        if (!c.fp.empty())  j += "          \"fingerprint\": \"" + JsonEsc(c.fp) + "\",\n";
        if (!c.alpn.empty()) {
            j += "          \"alpn\": [";
            // alpn в ссылке — строка через запятую (h2,http/1.1)
            std::wstring a = c.alpn; size_t pos = 0; bool first = true;
            while (pos <= a.size()) {
                size_t cm = a.find(L',', pos);
                std::wstring one = a.substr(pos, (cm == std::wstring::npos) ? std::wstring::npos : cm - pos);
                if (!one.empty()) { if (!first) j += ", "; j += "\"" + JsonEsc(one) + "\""; first = false; }
                if (cm == std::wstring::npos) break;
                pos = cm + 1;
            }
            j += "],\n";
        }
        j += "          \"allowInsecure\": false\n";
        j += "        },\n";
    } else if (c.security == L"reality") {
        j += "        \"realitySettings\": {\n";
        j += "          \"serverName\": \"" + JsonEsc(c.sni.empty() ? c.host : c.sni) + "\",\n";
        j += "          \"fingerprint\": \"" + JsonEsc(c.fp.empty() ? L"chrome" : c.fp) + "\",\n";
        j += "          \"publicKey\": \"" + JsonEsc(c.pbk) + "\",\n";
        j += "          \"shortId\": \"" + JsonEsc(c.sid) + "\",\n";
        j += "          \"spiderX\": \"" + JsonEsc(c.spiderX.empty() ? L"/" : c.spiderX) + "\"\n";
        j += "        },\n";
    }
    if (c.network == L"ws") {
        j += "        \"wsSettings\": {\n";
        j += "          \"path\": \"" + JsonEsc(c.path.empty() ? L"/" : c.path) + "\"";
        if (!c.hostHeader.empty())
            j += ",\n          \"headers\": {\"Host\": \"" + JsonEsc(c.hostHeader) + "\"}";
        j += "\n        },\n";
    } else if (c.network == L"grpc") {
        j += "        \"grpcSettings\": {\n";
        j += "          \"serviceName\": \"" + JsonEsc(c.serviceName) + "\"\n";
        j += "        },\n";
    }
    j += "        \"sockopt\": {\"tcpKeepAliveIdle\": 100, \"tcpNoDelay\": true}\n";
    j += "      }\n";
    j += "    },\n";
    j += "    {\"tag\": \"direct\", \"protocol\": \"freedom\", \"settings\": {}},\n";
    j += "    {\"tag\": \"block\", \"protocol\": \"blackhole\", \"settings\": {}}\n";
    j += "  ],\n";
    j += "  \"routing\": {\n";
    j += "    \"domainStrategy\": \"AsIs\",\n";
    j += "    \"rules\": [\n";
    j += "      {\"type\": \"field\", \"ip\": [\"127.0.0.1\", \"::1\", \"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\"], \"outboundTag\": \"direct\"}\n";
    j += "    ]\n";
    j += "  }\n";
    j += "}\n";
    return j;
}
