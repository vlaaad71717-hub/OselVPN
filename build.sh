#!/usr/bin/env bash
# build.sh — сборка OselVPN.exe из исходников.
# Зависимости: Python 3, Zig 0.13.0, файл xray.exe рядом с исходниками.
#
# Использование:
#   export ZIG=/path/to/zig             # по умолчанию: ~/tools/zig-linux-x86_64-0.13.0/zig
#   ./build.sh
#
# Перед первым запуском положи сюда:
#   xray.exe   (https://github.com/XTLS/Xray-core/releases/latest → Xray-windows-64.zip)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

ZIG="${ZIG:-$HOME/tools/zig-linux-x86_64-0.13.0/zig}"
PYTHON="${PYTHON:-python3}"

echo "==> Проверка зависимостей"
[[ -x "$ZIG" ]] || { echo "ОШИБКА: Zig не найден в $ZIG. Установи: https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz"; exit 1; }
command -v "$PYTHON" >/dev/null 2>&1 || { echo "ОШИБКА: python3 не найден в PATH"; exit 1; }

if [[ ! -f xray.exe ]]; then
    echo "ОШИБКА: xray.exe не найден в $HERE"
    echo "  Скачай: https://github.com/XTLS/Xray-core/releases/latest"
    echo "  Распакуй Xray-windows-64.zip и положи xray.exe сюда."
    exit 1
fi

echo "==> Упаковка xray.exe в COFF-объект (xray_payload.o)"
"$PYTHON" tools/gen_payload_coff.py xray.exe xray_payload.o

echo "==> Кросс-компиляция OselVPN.exe (Windows x64, GUI, static)"
"$ZIG" c++ -target x86_64-windows-gnu -O2 -static -s \
    -Wl,--subsystem,windows \
    OselVPN.cpp xray_payload.o \
    -lws2_32 -lwininet -ladvapi32 -luser32 -lgdi32 \
    -o OselVPN.exe

echo "==> Готово: $HERE/OselVPN.exe ($(du -h OselVPN.exe | cut -f1))"
