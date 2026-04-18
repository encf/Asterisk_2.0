#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
FIELD_PRIME=18446744073709551557
source "${ROOT_DIR}/scripts/lib_localhost_runner.sh"

N=3
REPEAT=5
LX=16
SLACK=8
X_CLEAR=0
BASE_PORT=""
LABEL=""
OUT_DIR="${ROOT_DIR}/run_logs/eqz_compare"

usage() {
  cat <<'EOF'
Usage: scripts/compare_eqz_a2.sh [options]

Benchmark standalone Asterisk2.0 EQZ across:
  - semi-honest
  - malicious

The script assumes your desired tc/netem rules are already active.
It does not modify the network configuration.

Measurements:
  1) single EQZ offline communication/time
  2) single EQZ online communication/time
  3) reconstructed correctness (and MAC consistency for malicious)

Options:
  -n, --num-parties <int>       Number of computing parties (default: 3)
  -r, --repeat <int>            Number of repetitions averaged in the summary (default: 5)
  --lx <int>                    EQZ lx parameter (default: 16)
  --slack <int>                 EQZ slack parameter s (default: 8)
  --x, --x-clear <int>          Clear signed input x (default: 0)
  -p, --base-port <int>         Base port (default: auto-pick a free range)
  --label <text>                Optional scenario label for the summary output
  -o, --out-dir <path>          Output directory (default: run_logs/eqz_compare)
  -h, --help                    Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -r|--repeat) REPEAT="$2"; shift 2 ;;
    --lx) LX="$2"; shift 2 ;;
    --slack) SLACK="$2"; shift 2 ;;
    --x|--x-clear) X_CLEAR="$2"; shift 2 ;;
    -p|--base-port) BASE_PORT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    -o|--out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -n "${LABEL}" ]]; then
  RUN_OUT_DIR="${OUT_DIR}/${LABEL}"
else
  RUN_OUT_DIR="${OUT_DIR}/run_$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "${RUN_OUT_DIR}"

if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache >/dev/null
fi
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target asterisk2_eqz >/dev/null

TOTAL_PARTIES=$((N + 1))
PORT_STRIDE="$(localhost_compute_port_stride "${TOTAL_PARTIES}" 64)"
TOTAL_PORT_WIDTH=$((2 * PORT_STRIDE))

if [[ -n "${BASE_PORT}" ]]; then
  localhost_ensure_base_port_available "${BASE_PORT}" "${TOTAL_PORT_WIDTH}"
else
  BASE_PORT="$(localhost_pick_free_base_port "${TOTAL_PORT_WIDTH}")"
fi

run_case() {
  local model="$1"
  local port="$2"
  local run_dir="${RUN_OUT_DIR}/${model}"
  echo "[RUN] model=${model}, repeat=${REPEAT}, x=${X_CLEAR}, port=${port}"
  localhost_run_multiparty_group "${run_dir}" "${N}" "${port}" "${PORT_STRIDE}" \
    "${BUILD_DIR}/benchmarks/asterisk2_eqz" \
    --security-model "${model}" -r "${REPEAT}" \
    --lx "${LX}" --slack "${SLACK}" --x-clear "${X_CLEAR}"
  echo "[DONE] model=${model}"
}

run_case semi-honest "${BASE_PORT}"
run_case malicious "$((BASE_PORT + PORT_STRIDE))"

python3 - "${RUN_OUT_DIR}" "${N}" "${REPEAT}" "${LABEL}" "${LX}" "${SLACK}" "${X_CLEAR}" "${FIELD_PRIME}" <<'PY'
import json
import pathlib
import statistics
import sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
repeat = int(sys.argv[3])
label = sys.argv[4]
lx = int(sys.argv[5])
slack = int(sys.argv[6])
x_clear = int(sys.argv[7])
prime = int(sys.argv[8])
MB = 1024 * 1024

expected = 1 if x_clear == 0 else 0

def load_model(model):
    return [json.loads((out_dir / model / f"p{pid}.json").read_text()) for pid in range(n + 1)]

def summarize(model, malicious):
    parties = load_model(model)
    off_comm, off_time, on_comm, on_time = [], [], [], []
    reconstructed = []
    mac_ok_all = True
    for r in range(repeat):
        off_b = on_b = 0
        off_ms = on_ms = 0.0
        out = 0
        delta_out = 0
        delta = 0
        for pid in range(n + 1):
            row = parties[pid]["benchmarks"][r]
            off_b += int(row["offline_bytes"])
            on_b += int(row["online_bytes"])
            off_ms = max(off_ms, float(row["offline"]["time"]))
            on_ms = max(on_ms, float(row["online"]["time"]))
            if pid < n:
                out = (out + int(row["output_share"])) % prime
                if malicious:
                    delta_out = (delta_out + int(row["delta_output_share"])) % prime
                    delta = (delta + int(row["delta_share"])) % prime
        off_comm.append(off_b / MB)
        on_comm.append(on_b / MB)
        off_time.append(off_ms / 1000.0)
        on_time.append(on_ms / 1000.0)
        reconstructed.append(out)
        if malicious:
            mac_ok_all = mac_ok_all and (delta_out == (delta * out) % prime)
    value_ok = all(v == expected for v in reconstructed)
    return {
        "offline_comm_mb": statistics.mean(off_comm),
        "offline_time_s": statistics.mean(off_time),
        "online_comm_mb": statistics.mean(on_comm),
        "online_time_s": statistics.mean(on_time),
        "reconstructed_outputs": reconstructed,
        "value_check_passed": value_ok,
        "mac_check_passed": mac_ok_all if malicious else None,
    }

sh = summarize("semi-honest", False)
mal = summarize("malicious", True)

summary = {
    "label": label,
    "num_parties": n,
    "repeat": repeat,
    "parameters": {
        "lx": lx,
        "slack": slack,
        "x_clear": x_clear,
        "expected_eqz": expected,
    },
    "semi_honest": sh,
    "malicious": mal,
}

(out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

title = "=== Asterisk2.0 Standalone EQZ Summary ==="
if label:
    title += f" [{label}]"
print("\n" + title)
print("| Security Model | Offline Comm (MB) | Offline Time (s) | Online Comm (MB) | Online Time (s) | Correct |")
print("|---|---:|---:|---:|---:|---|")
print(f"| semi-honest | {sh['offline_comm_mb']:.6f} | {sh['offline_time_s']:.6f} | {sh['online_comm_mb']:.6f} | {sh['online_time_s']:.6f} | {'PASS' if sh['value_check_passed'] else 'FAIL'} |")
mal_ok = mal["value_check_passed"] and mal["mac_check_passed"]
print(f"| malicious | {mal['offline_comm_mb']:.6f} | {mal['offline_time_s']:.6f} | {mal['online_comm_mb']:.6f} | {mal['online_time_s']:.6f} | {'PASS' if mal_ok else 'FAIL'} |")
print(f"\n[INFO] Expected EQZ({x_clear}) = {expected}")
print(f"[INFO] Machine-readable summary: {out_dir / 'summary.json'}")
PY

echo
echo "[DONE] Raw JSON written to: ${RUN_OUT_DIR}"
