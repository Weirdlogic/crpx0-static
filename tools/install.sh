#!/usr/bin/env bash
# Install the pinned analysis toolchain into ~/.local/opt and link it into ~/.local/bin.
# Every download is checked against the SHA-256 published on its GitHub release
# before it is unpacked. Re-running is safe: installed versions are skipped.
set -euo pipefail

OPT="$HOME/.local/opt"
BIN="$HOME/.local/bin"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/research-tools"
mkdir -p "$OPT" "$BIN" "$CACHE"

GHIDRA_VER=12.1.4
GHIDRA_ZIP=ghidra_12.1.4_PUBLIC_20260921.zip
GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/$GHIDRA_ZIP
GHIDRA_SHA=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db

CAPA_VER=9.4.0
CAPA_URL=https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux.zip
CAPA_SHA=07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4

FLOSS_VER=3.1.1
FLOSS_URL=https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip
FLOSS_SHA=40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666  # first-download hash 2026-10-13; release publishes none

YARAX_VER=1.21.0
YARAX_URL=https://github.com/VirusTotal/yara-x/releases/download/v1.21.0/yara-x-v1.21.0-x86_64-unknown-linux-gnu.tar.gz
YARAX_SHA=01585181e8979e36ac10ab123fcf8921cf8ba879bf942916413e091e18d64852

REA_VER=6.4.0
REA_INTEGRITY=sha512-Vj1zWfSlna5bphGoaoI/TcVBuYvze9u+OyPC3Shz8YkBqaCTqB4COnnRoX7XDwMpwI24ZlFEel2yEj0k8LTWEQ==

DOTNET_VER=10.0.13  # security release 2026-10-13; runtime only
DOTNET_URL=https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.13/dotnet-runtime-10.0.13-linux-x64.tar.gz
DOTNET_SHA512=9574d95364110409416735e7842796f8d614c21d74cb25d204a3e4cfd11b2c05efdf19ca89b8069650a04f64add2705967dcb04b8665a36d7a3f30a5d8c05afe

ILSPY_VER=11.1.0.9782
ILSPY_URL=https://api.nuget.org/v3-flatcontainer/ilspycmd/11.1.0.9782/ilspycmd.11.1.0.9782.nupkg
ILSPY_NUGET_SHA512=F7Clu/rYWPt9fClDLzZgWXI0N2/Rt44t5tOukOYUZt1tI8kwZTCY8zEZVgIr7eTkJQhuZFJW6RJ8HzRClwnIQg==

JAVA_HOME_DEFAULT="$OPT/jdk-21.0.12.1+1"

fetch() {  # url sha256 -> path in cache
  local url=$1 sha=$2 out="$CACHE/$(basename "$1")"
  [ -f "$out" ] || curl -fL --retry 3 -o "$out.part" "$url" && { [ -f "$out" ] || mv "$out.part" "$out"; }
  local got; got=$(sha256sum "$out" | cut -d' ' -f1)
  if [ -n "$sha" ] && [ "$got" != "$sha" ]; then
    echo "SHA-256 MISMATCH for $url: got $got want $sha" >&2; rm -f "$out"; exit 1
  fi
  echo "  sha256 $got  $(basename "$out")" >&2
  echo "$out"
}

link() { ln -sfn "$1" "$BIN/$2"; }

echo "== Ghidra $GHIDRA_VER"
if [ ! -d "$OPT/ghidra_${GHIDRA_VER}_PUBLIC" ]; then
  z=$(fetch "$GHIDRA_URL" "$GHIDRA_SHA"); unzip -q "$z" -d "$OPT"
fi
link "$OPT/ghidra_${GHIDRA_VER}_PUBLIC/ghidraRun" ghidra
link "$OPT/ghidra_${GHIDRA_VER}_PUBLIC/support/analyzeHeadless" analyzeHeadless

echo "== capa $CAPA_VER"
if [ ! -x "$OPT/capa-$CAPA_VER/capa" ]; then
  z=$(fetch "$CAPA_URL" "$CAPA_SHA"); mkdir -p "$OPT/capa-$CAPA_VER"; unzip -qo "$z" -d "$OPT/capa-$CAPA_VER"; chmod +x "$OPT/capa-$CAPA_VER/capa"
fi
link "$OPT/capa-$CAPA_VER/capa" capa

echo "== FLOSS $FLOSS_VER"
if [ ! -x "$OPT/floss-$FLOSS_VER/floss" ]; then
  z=$(fetch "$FLOSS_URL" "$FLOSS_SHA"); mkdir -p "$OPT/floss-$FLOSS_VER"; unzip -qo "$z" -d "$OPT/floss-$FLOSS_VER"; chmod +x "$OPT/floss-$FLOSS_VER/floss"
fi
link "$OPT/floss-$FLOSS_VER/floss" floss

echo "== YARA-X $YARAX_VER"
if [ ! -x "$OPT/yara-x-$YARAX_VER/yr" ]; then
  z=$(fetch "$YARAX_URL" "$YARAX_SHA"); mkdir -p "$OPT/yara-x-$YARAX_VER"; tar -xzf "$z" -C "$OPT/yara-x-$YARAX_VER"
fi
link "$OPT/yara-x-$YARAX_VER/yr" yr

echo "== rea $REA_VER"
if [ ! -x "$OPT/rea-$REA_VER/node_modules/.bin/rea" ]; then
  mkdir -p "$OPT/rea-$REA_VER"
  # --ignore-scripts: no dependency lifecycle scripts run at install time.
  npm install --prefix "$OPT/rea-$REA_VER" --ignore-scripts --no-audit --no-fund "rea-agents@$REA_VER"
  got=$(node -p "require('$OPT/rea-$REA_VER/package-lock.json').packages['node_modules/rea-agents'].integrity")
  [ "$got" = "$REA_INTEGRITY" ] || { echo "rea integrity mismatch: $got" >&2; exit 1; }
fi
link "$OPT/rea-$REA_VER/node_modules/.bin/rea" rea

echo "== .NET runtime $DOTNET_VER (runtime only, for ilspycmd)"
if [ ! -x "$OPT/dotnet-$DOTNET_VER/dotnet" ]; then
  t=$(fetch "$DOTNET_URL" "")
  echo "$DOTNET_SHA512  $t" | sha512sum -c --quiet - || { echo "dotnet SHA-512 mismatch" >&2; rm -f "$t"; exit 1; }
  mkdir -p "$OPT/dotnet-$DOTNET_VER"; tar -xzf "$t" -C "$OPT/dotnet-$DOTNET_VER"
fi

echo "== ilspycmd $ILSPY_VER"
if [ ! -f "$OPT/ilspycmd-$ILSPY_VER/tools/net10.0/any/ilspycmd.dll" ]; then
  n=$(fetch "$ILSPY_URL" "")
  got=$(python3 -c "import hashlib,base64,sys;print(base64.b64encode(hashlib.sha512(open(sys.argv[1],'rb').read()).digest()).decode())" "$n")
  [ "$got" = "$ILSPY_NUGET_SHA512" ] || { echo "ilspycmd hash mismatch" >&2; rm -f "$n"; exit 1; }
  mkdir -p "$OPT/ilspycmd-$ILSPY_VER"; unzip -qo "$n" 'tools/*' -d "$OPT/ilspycmd-$ILSPY_VER"
fi
cat > "$BIN/ilspycmd" <<EOF
#!/bin/sh
DOTNET_ROOT="$OPT/dotnet-$DOTNET_VER" DOTNET_CLI_TELEMETRY_OPTOUT=1 exec "$OPT/dotnet-$DOTNET_VER/dotnet" "$OPT/ilspycmd-$ILSPY_VER/tools/net10.0/any/ilspycmd.dll" "\$@"
EOF
chmod +x "$BIN/ilspycmd"

echo "== Java for Ghidra"
if ! command -v java >/dev/null; then
  echo "  java not on PATH; Ghidra will use JAVA_HOME=$JAVA_HOME_DEFAULT (see tools/env.sh)"
fi
echo "done"
