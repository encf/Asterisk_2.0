#!/usr/bin/env bash
set -euo pipefail

# One-click dependency installer for Ubuntu (22.04/24.04 tested).
# It installs system packages and builds emp-tool from source into /usr/local.

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "[1/3] Installing Ubuntu packages..."
${SUDO} apt-get update
${SUDO} apt-get install -y \
  build-essential \
  ccache \
  cmake \
  git \
  pkg-config \
  libgmp-dev \
  libntl-dev \
  libboost-all-dev \
  nlohmann-json3-dev \
  libssl-dev

echo "[2/3] Building and installing emp-tool from local source..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EMP_TOOL_LOCAL_DIR="${SCRIPT_DIR}/../emp-tool"
if [[ ! -d "${EMP_TOOL_LOCAL_DIR}" ]]; then
  echo "Local emp-tool directory not found: ${EMP_TOOL_LOCAL_DIR}" >&2
  exit 1
fi

cmake -S "${EMP_TOOL_LOCAL_DIR}" -B "${EMP_TOOL_LOCAL_DIR}/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
cmake --build "${EMP_TOOL_LOCAL_DIR}/build" -j"$(nproc)"
${SUDO} cmake --install "${EMP_TOOL_LOCAL_DIR}/build"

echo "[2.5/3] Configuring ccache..."
ccache --max-size=10G >/dev/null 2>&1 || true

echo "[3/3] Done."
echo "Now configure and build Asterisk:"
echo "  mkdir -p build && cd build"
echo "  cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache .."
echo "  make -j\$(nproc) tests benchmarks"
