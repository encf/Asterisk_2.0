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

cmake -S "${EMP_TOOL_LOCAL_DIR}" -B "${EMP_TOOL_LOCAL_DIR}/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "${EMP_TOOL_LOCAL_DIR}/build" -j"$(nproc)"
${SUDO} cmake --install "${EMP_TOOL_LOCAL_DIR}/build"

echo "[3/3] Done."
echo "Now configure and build Asterisk:"
echo "  mkdir -p build && cd build"
echo "  cmake -DCMAKE_BUILD_TYPE=Release .."
echo "  make -j\$(nproc) tests benchmarks"
