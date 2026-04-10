#!/usr/bin/env bash
set -euo pipefail

# One-click dependency installer for Ubuntu (22.04/24.04 tested).
# It installs system packages and installs emp-tool via emp-readme installer.

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "[1/3] Installing Ubuntu packages..."
${SUDO} apt-get update
${SUDO} apt-get install -y \
  build-essential \
  cmake \
  git \
  pkg-config \
  libgmp-dev \
  libntl-dev \
  libboost-all-dev \
  nlohmann-json3-dev \
  libssl-dev \
  wget \
  python3

echo "[2/3] Installing emp-tool via emp-readme installer..."
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
cd "${WORKDIR}"
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python install.py --deps --tool

echo "[3/3] Done."
echo "Now configure and build Asterisk:"
echo "  mkdir -p build && cd build"
echo "  cmake -DCMAKE_BUILD_TYPE=Release .."
echo "  make -j\$(nproc) tests benchmarks"
