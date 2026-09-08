#!/bin/sh
set -eu
cd "$(dirname "$0")"
BEAR_VER=0.6
BEAR_URL="https://www.bearssl.org/bearssl-${BEAR_VER}.tar.gz"
BEAR_SHA256="6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14"
CC="${CC:-musl-gcc}"
need() { command -v "$1" >/dev/null 2>&1 || { echo "build.sh: need $1" >&2; exit 1; }; }
need "$CC"; need openssl; need strip; need python3
# used later: curl/tar (only when downloading), sha256sum -c (digest verify),
# stat -c%s and file -b (final report line) — GNU coreutils assumptions
need sha256sum; need stat; need file; need cut
if [ ! -d build/bearssl ]; then
  need curl; need tar
fi
mkdir -p build
if [ ! -d build/bearssl ]; then
  if [ ! -f build/bearssl.tar.gz ]; then
    echo "build.sh: downloading BearSSL $BEAR_VER ..."
    curl -fsSL --max-time 120 -o build/bearssl.tar.gz "$BEAR_URL"
  fi
  echo "build.sh: verifying checksum ..."
  echo "$BEAR_SHA256  build/bearssl.tar.gz" | sha256sum -c -
  rm -rf "build/bearssl-src"
  mkdir -p build/bearssl-src
  tar xzf build/bearssl.tar.gz -C build/bearssl-src
  mv "build/bearssl-src/bearssl-$BEAR_VER" build/bearssl
fi
python3 - <<'EOF'
import subprocess
outs = []
for name in ("anchors/isrgx1.pem", "anchors/isrgx2.pem", "anchors/gtsr4.pem"):
    der = subprocess.run(["openssl", "x509", "-in", name, "-outform", "DER"],
                         capture_output=True, check=True).stdout
    outs.append((name, der))
total = sum(len(d) for _, d in outs)
assert total < 4096, total
with open("build/anchors.h", "w") as f:
    for i, (name, der) in enumerate(outs):
        f.write(f"static const unsigned char anchor_der_{i}[] = {{\n")
        for j in range(0, len(der), 12):
            f.write(",".join(str(b) for b in der[j:j+12]) + ",\n")
        f.write("};\n")
    f.write("static const unsigned char *const g_anchor_der[] = {\n")
    for i in range(len(outs)):
        f.write(f"  anchor_der_{i},\n")
    f.write("};\nstatic const unsigned g_anchor_len[] = {\n")
    for _, der in outs:
        f.write(f"  {len(der)}u,\n")
    f.write("};\n#define N_ANCHORS %d\n" % len(outs))
print("anchors DER total: %d bytes (<4KB)" % total)
EOF
mkdir -p build/obj
BearSSL_SRCS="build/bearssl/src/*/*.c"
n=0
for s in $BearSSL_SRCS; do
  o="build/obj/$(echo "$s" | tr '/.' '__').o"
  if [ ! -f "$o" ] || [ "$s" -nt "$o" ]; then
    $CC -std=c11 -Os -ffunction-sections -fdata-sections \
      -idirafter /usr/include \
      -I build/bearssl/inc -I build/bearssl/src -c "$s" -o "$o"
    n=$((n+1))
  fi
done
echo "build.sh: compiled $n bearssl objects (cached rest)"
$CC -std=c11 -Os -ffunction-sections -fdata-sections -Wall -Wextra \
  -idirafter /usr/include \
  -I build -I build/bearssl/inc -I build/bearssl/src \
  transcriber.c build/obj/*.o \
  -o build/transcriber -static -Wl,--gc-sections
strip build/transcriber
# policy: binaries install to ~/.local/bin ONLY, never the project root (see README.md)
install_bin="${HOME:?}/.local/bin"
mkdir -p "$install_bin"
# atomic replace: a plain `cp` onto the destination fails with ETXTBSY while
# the daemon is running; rename(2) over a running binary is allowed (the
# old process keeps its inode) and the new file takes effect on restart.
cp build/transcriber "$install_bin/transcriber.new"
mv -f "$install_bin/transcriber.new" "$install_bin/transcriber"
echo "build.sh: OK: installed $install_bin/transcriber ($(stat -c%s "$install_bin/transcriber") bytes static: $(file -b "$install_bin/transcriber" | cut -c1-80))"
