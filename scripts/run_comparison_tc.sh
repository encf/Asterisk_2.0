#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPARE_SCRIPT="${ROOT_DIR}/scripts/compare_cmp_protocols.sh"
OUT_DIR="${ROOT_DIR}/run_logs/comparison_tc"

BANDWIDTH="100mbit"
ONE_WAY_DELAY_MS=20
N=5
COMPARE_COUNT=1
LX=16
SLACK=8
BASE_PORT=""
PING_COUNT=5
CLEAR_TC_ON_EXIT=1
SKIP_TC=0
LABEL=""

usage() {
  cat <<'EOF'
Usage: scripts/run_comparison_tc.sh [options]

Configure loopback tc/netem, run the comparison benchmark, and save the
network snapshot together with benchmark outputs.

Options:
  -n, --num-parties <int>       Number of computing parties (default: 5)
  -c, --compare-count <int>     Number of comparisons (default: 1)
  --lx <int>                    BGTEZ lx parameter (default: 16)
  --slack <int>                 BGTEZ slack parameter s (default: 8)
  --delay <int>                 Symmetric one-way delay in ms on `lo` (default: 20)
  --bandwidth <rate>            tc rate, e.g. 100mbit (default: 100mbit)
  --base-port <int>             Base port for benchmark processes (default: auto-pick)
  --ping-count <int>            ping probes used after tc setup (default: 5)
  --label <text>                Optional label for saved outputs
  --out-dir <path>              Output directory (default: run_logs/comparison_tc)
  --skip-tc                     Do not modify tc/ping; run on the current local network as-is
  --keep-tc                     Keep the final tc rule instead of clearing it on exit
  -h, --help                    Show help
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

ensure_sudo_ready() {
  if ! sudo -n true 2>/dev/null; then
    echo "This script needs sudo access to configure tc on loopback (lo)." >&2
    echo "Please run it from an interactive terminal where sudo can prompt for your password," >&2
    echo "or pre-authorize sudo before invoking the script." >&2
    exit 1
  fi
}

validate_port_range() {
  local port="$1"
  local total_parties=$2
  local case_stride=$((2 * total_parties * total_parties + 64))
  local max_port_needed=$((port + 4 * case_stride - 1))
  if (( port < 1024 || max_port_needed > 65535 )); then
    echo "Invalid --base-port=${port}: this wrapper needs ports up to ${max_port_needed}, which must stay within 1024..65535." >&2
    exit 1
  fi
}

clear_tc() {
  sudo tc qdisc del dev lo root 2>/dev/null || true
}

set_tc() {
  local delay_ms="$1"
  clear_tc
  sudo tc qdisc add dev lo root netem delay "${delay_ms}ms" rate "${BANDWIDTH}"
}

show_tc() {
  tc qdisc show dev lo
}

measure_ping_avg_ms() {
  local log_file="$1"
  ping -n -c "${PING_COUNT}" 127.0.0.1 | tee "${log_file}" >/dev/null
  python3 - "${log_file}" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/", text)
print(match.group(2) if match else "NA")
PY
}

cleanup() {
  if [[ "${SKIP_TC}" -eq 0 && "${CLEAR_TC_ON_EXIT}" -eq 1 ]]; then
    clear_tc
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -c|--compare-count) COMPARE_COUNT="$2"; shift 2 ;;
    --lx) LX="$2"; shift 2 ;;
    --slack) SLACK="$2"; shift 2 ;;
    --delay) ONE_WAY_DELAY_MS="$2"; shift 2 ;;
    --bandwidth) BANDWIDTH="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --ping-count) PING_COUNT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --skip-tc) SKIP_TC=1; shift ;;
    --keep-tc) CLEAR_TC_ON_EXIT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

require_cmd python3
if [[ "${SKIP_TC}" -eq 0 ]]; then
  require_cmd sudo
  require_cmd tc
  require_cmd ping
fi

if [[ ! -x "${COMPARE_SCRIPT}" ]]; then
  echo "Expected executable compare script at ${COMPARE_SCRIPT}" >&2
  exit 1
fi

if [[ "${SKIP_TC}" -eq 0 ]]; then
  ensure_sudo_ready
fi

if [[ -n "${BASE_PORT}" ]]; then
  validate_port_range "${BASE_PORT}" "$((N + 1))"
fi

if [[ -z "${LABEL}" ]]; then
  LABEL="cmp_owd_${ONE_WAY_DELAY_MS}ms_n${N}"
fi

RUN_DIR="${OUT_DIR}/${LABEL}"
RAW_DIR="${RUN_DIR}/raw"
mkdir -p "${RUN_DIR}"

trap cleanup EXIT

if [[ "${SKIP_TC}" -eq 0 ]]; then
  echo "=== Configuring loopback tc: bandwidth=${BANDWIDTH}, one-way delay=${ONE_WAY_DELAY_MS}ms ==="
  set_tc "${ONE_WAY_DELAY_MS}"
  show_tc | tee "${RUN_DIR}/tc_qdisc.txt"
  echo "[INFO] Measuring loopback ping..."
  PING_AVG_MS="$(measure_ping_avg_ms "${RUN_DIR}/ping.txt")"
  {
    echo "network_mode=tc_lo"
    echo "interface=lo"
    echo "bandwidth=${BANDWIDTH}"
    echo "one_way_delay_ms=${ONE_WAY_DELAY_MS}"
    echo "approx_rtt_ms=$((ONE_WAY_DELAY_MS * 2))"
    echo "measured_ping_avg_ms=${PING_AVG_MS}"
    echo "num_parties=${N}"
    echo "compare_count=${COMPARE_COUNT}"
    echo "lx=${LX}"
    echo "slack=${SLACK}"
  } > "${RUN_DIR}/env.txt"
else
  echo "=== Skipping tc configuration; running on the current local network ==="
  {
    echo "network_mode=unchanged_local"
    echo "interface=lo"
    echo "bandwidth=unchanged"
    echo "one_way_delay_ms=unchanged"
    echo "approx_rtt_ms=unchanged"
    echo "measured_ping_avg_ms=NA"
    echo "num_parties=${N}"
    echo "compare_count=${COMPARE_COUNT}"
    echo "lx=${LX}"
    echo "slack=${SLACK}"
  } > "${RUN_DIR}/env.txt"
fi

compare_cmd=(
  "${COMPARE_SCRIPT}"
  -n "${N}"
  -c "${COMPARE_COUNT}"
  --lx "${LX}"
  --slack "${SLACK}"
  --label "${LABEL}"
  -o "${RAW_DIR}"
)

if [[ -n "${BASE_PORT}" ]]; then
  compare_cmd+=(-p "${BASE_PORT}")
fi

"${compare_cmd[@]}" | tee "${RUN_DIR}/compare_output.txt"

echo
echo "[DONE] Comparison tc run saved to: ${RUN_DIR}"
