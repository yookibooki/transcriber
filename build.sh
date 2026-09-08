#!/bin/sh
set -eu
cd "$(dirname "$0")"
BEAR_VER=0.6
BEAR_URL="https://www.bearssl.org/bearssl-${BEAR_VER}.tar.gz"
BEAR_SHA256="6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14"
CC="${CC:-musl-gcc}"
need() { command -v "$1" >/dev/null 2>&1 || { echo "build.sh: need $1" >&2; exit 1; }; }
need "$CC" strip sha256sum stat file cut tr systemctl
mkdir -p build
if [ ! -d build/bearssl ]; then
  need curl tar
  if [ ! -f build/bearssl.tar.gz ]; then
    echo "downloading BearSSL $BEAR_VER ..."
    curl -fsSL --max-time 120 -o build/bearssl.tar.gz "$BEAR_URL"
  fi
  echo "verifying checksum ..."
  echo "$BEAR_SHA256  build/bearssl.tar.gz" | sha256sum -c -
  rm -rf build/bearssl-src
  mkdir -p build/bearssl-src
  tar xzf build/bearssl.tar.gz -C build/bearssl-src
  mv "build/bearssl-src/bearssl-$BEAR_VER" build/bearssl
fi
mkdir -p build/obj
n=0
for s in build/bearssl/src/*.c build/bearssl/src/*/*.c build/bearssl/tools/*.c; do
  o="build/obj/$(echo "$s" | tr '/.' '__').o"
  if [ ! -f "$o" ] || [ "$s" -nt "$o" ]; then
    $CC -std=c11 -Os -ffunction-sections -fdata-sections \
      -idirafter /usr/include \
      -I build/bearssl/inc -I build/bearssl/src -c "$s" -o "$o"
    n=$((n+1))
  fi
done
echo "compiled $n objects (cached rest)"
$CC build/obj/*.o -o build/brssl -static -Wl,--gc-sections
build/brssl ta -q anchors/*.pem > build/ta.h
set -- anchors/*.pem
grep -qE "^#define TAs_NUM +${#}$" build/ta.h \
  || { echo "build.sh: anchor table mismatch (expected ${#} anchors)" >&2; exit 1; }
echo "${#} trust anchors -> build/ta.h"
$CC -std=c11 -Os -ffunction-sections -fdata-sections -Wall -Wextra \
  -idirafter /usr/include \
  -I build -I build/bearssl/inc -I build/bearssl/src \
  transcriber.c build/obj/build_bearssl_src_*.o \
  -o build/transcriber -static -Wl,--gc-sections
strip build/transcriber
install_bin="${HOME:?}/.local/bin"
mkdir -p "$install_bin"
cp build/transcriber "$install_bin/transcriber.new"
mv -f "$install_bin/transcriber.new" "$install_bin/transcriber"
systemctl restart --user transcriber
echo "OK: installed and restarted $install_bin/transcriber ($(stat -c%s "$install_bin/transcriber") bytes static: $(file -b "$install_bin/transcriber" | cut -c1-80))"
