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

echo "[2/3] Building and installing emp-tool..."
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

EMP_TOOL_GIT_URL="${EMP_TOOL_GIT_URL:-https://github.com/emp-toolkit/emp-tool.git}"
if ! git clone --depth 1 "${EMP_TOOL_GIT_URL}" "${WORKDIR}/emp-tool"; then
  echo "Failed to clone emp-tool from: ${EMP_TOOL_GIT_URL}" >&2
  echo "If GitHub is blocked in your environment, rerun with a reachable mirror, e.g.:" >&2
  echo "  EMP_TOOL_GIT_URL=<mirror-url> ./scripts/install_deps_ubuntu.sh" >&2
  exit 1
fi
cmake -S "${WORKDIR}/emp-tool" -B "${WORKDIR}/emp-tool/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "${WORKDIR}/emp-tool/build" -j"$(nproc)"
${SUDO} cmake --install "${WORKDIR}/emp-tool/build"

echo "[3/3] Done."
echo "Now configure and build Asterisk:"
echo "  mkdir -p build && cd build"
echo "  cmake -DCMAKE_BUILD_TYPE=Release .."
echo "  make -j\$(nproc) tests benchmarks"
