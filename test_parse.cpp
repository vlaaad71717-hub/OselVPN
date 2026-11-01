// Тест парсера vless.h на Linux: печатает config.json для примеров ссылок.
#include "vless.h"
#include <cstdio>
#include <string>

static void dump(const std::string& title, const std::wstring& link, int i) {
    VlessConfig c = ParseVless(link);
    printf("=== %s ===\n", title.c_str());
    if (!c.ok) { printf("PARSE ERROR: %ls\n", c.error.c_str()); return; }
    printf("name=%ls uuid=%ls host=%ls port=%ls sec=%ls net=%ls flow=%ls\n",
           c.name.c_str(), c.uuid.c_str(), c.host.c_str(), c.port.c_str(),
           c.security.c_str(), c.network.c_str(), c.flow.c_str());
    std::string fn = "/tmp/vless_test_" + std::to_string(i) + ".json";
    FILE* f = fopen(fn.c_str(), "wb");
    fputs(BuildXrayConfig(c, 10808, 10809).c_str(), f);
    fclose(f);
    printf("written %s\n\n", fn.c_str());
}

int main() {
    dump("REALITY+vision",
         L"vless://a1b2c3d4-1111-2222-3333-abcdefabcdef@example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=Xj8xYkQF9k0Z1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT&sid=ab12cd34&type=tcp&flow=xtls-rprx-vision#OselVPN%20Test%201",
         1);
    dump("TLS+ws",
         L"vless://a1b2c3d4-1111-2222-3333-abcdefabcdef@vpn.host.ru:443?encryption=none&security=tls&sni=cdn.host.ru&fp=safari&type=ws&path=%2Fws%2Fpath&host=cdn.host.ru&alpn=h2%2Chttp%2F1.1#Мой%20сервер",
         2);
    dump("gRPC+tls",
         L"vless://a1b2c3d4-1111-2222-3333-abcdefabcdef@1.2.3.4:2053?security=tls&type=grpc&serviceName=grpc-svc#grpc-test",
         3);
    dump("plain tcp no security",
         L"vless://a1b2c3d4-1111-2222-3333-abcdefabcdef@10.20.30.40:12345#plain",
         4);
    dump("broken (no @)",
         L"vless://example.com:443",
         5);
    return 0;
}
