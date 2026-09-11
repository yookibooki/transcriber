#!/bin/sh
set -eu
cd "$(dirname "$0")"
BEAR_VER=0.6
BEAR_URL="https://www.bearssl.org/bearssl-${BEAR_VER}.tar.gz"
BEAR_SHA256="6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14"
CC="${CC:-musl-gcc}"
need() { command -v "$1" >/dev/null 2>&1 || { echo "build.sh: need $1" >&2; exit 1; }; }
need "$CC" strip sha256sum stat file cut tr ar
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
BEAR_CFLAGS="-std=c11 -D_GNU_SOURCE -Os -flto -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -DNDEBUG"
for s in build/bearssl/src/*.c build/bearssl/src/*/*.c build/bearssl/tools/*.c; do
  o="build/obj/$(echo "$s" | tr '/.' '__').o"
  if [ ! -f "$o" ] || [ "$s" -nt "$o" ]; then
    $CC $BEAR_CFLAGS \
      -idirafter /usr/include \
      -I build/bearssl/inc -I build/bearssl/src -c "$s" -o "$o"
    n=$((n+1))
  fi
done
echo "compiled $n objects (cached rest)"
$CC $BEAR_CFLAGS build/obj/*.o -o build/brssl -static -Wl,--gc-sections
build/brssl ta -q anchors/*.pem > build/ta.h
set -- anchors/*.pem
grep -qE "^#define TAs_NUM +${#}$" build/ta.h \
  || { echo "build.sh: anchor table mismatch (expected ${#} anchors)" >&2; exit 1; }
echo "${#} trust anchors -> build/ta.h"

echo "checking anchor expiry..."
for pem in anchors/*.pem; do
  if command -v openssl >/dev/null 2>&1; then
    end=$(openssl x509 -noout -enddate -in "$pem" 2>/dev/null | cut -d= -f2 || true)
    if [ -n "$end" ]; then
      echo "  $pem -> $end"
      if openssl x509 -checkend $((90*24*3600)) -noout -in "$pem" 2>/dev/null; then
        :
      else
        echo "  WARNING: $pem expires within 90 days!" >&2
      fi
    fi
  else
    echo "  $pem (install openssl to check dates)"
  fi
done

ar rcs build/libbear.a build/obj/build_bearssl_src_*.o
$CC -std=c11 -Os -flto -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -DNDEBUG -Wall -Wextra \
  -idirafter /usr/include \
  -I build -I build/bearssl/inc -I build/bearssl/src \
  transcriber.c build/libbear.a \
  -o build/transcriber -static -Wl,--gc-sections
strip --strip-all build/transcriber

if [ -f tests.c ]; then
  echo "building unit tests..."
  $CC -std=c11 -Os -Wall -Wextra tests.c -o build/tests
  echo "running unit tests..."
  ./build/tests
fi

if [ -f transcriber.service ]; then
  unit_dest="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/transcriber.service"
  mkdir -p "$(dirname "$unit_dest")"
  if [ ! -f "$unit_dest" ] || ! cmp -s transcriber.service "$unit_dest"; then
    echo "installing systemd unit to $unit_dest"
    cp transcriber.service "$unit_dest"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl --user daemon-reload || true
    fi
  fi
fi

install_bin="${HOME:?}/.local/bin"
mkdir -p "$install_bin"
cp build/transcriber "$install_bin/transcriber.new"
mv -f "$install_bin/transcriber.new" "$install_bin/transcriber"
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user reset-failed transcriber 2>/dev/null || true
  systemctl --user restart transcriber || echo "build.sh: installed, but service restart failed (enable/start manually: systemctl --user enable --now transcriber)" >&2
else
  echo "build.sh: installed, no systemctl (non-systemd: start manually)" >&2
fi
echo "OK: installed and restarted $install_bin/transcriber ($(stat -c%s "$install_bin/transcriber") bytes static: $(file -b "$install_bin/transcriber" | cut -c1-80))"
