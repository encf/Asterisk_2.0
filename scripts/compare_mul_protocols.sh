#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
source "${ROOT_DIR}/scripts/lib_localhost_runner.sh"

N=5
CHAIN_MUL=10000
GATES_PER_LEVEL=1
REPEAT=1
BASE_PORT=""
OUT_DIR="${ROOT_DIR}/run_logs/protocol_compare"

usage() {
  cat <<'EOF'
Usage: scripts/compare_mul_protocols.sh [options]

Run and compare multiplication protocol benchmarks:
  1) Asterisk (offline + online split binaries)
  2) Asterisk2.0 semi-honest
  3) Asterisk2.0 malicious

Options:
  -n, --num-parties <int>      Number of computing parties (default: 5)
  -d, --chain-mul <int>        Continuous multiplication count / depth (default: 10000)
  -g, --gates-per-level <int>  Multiplication gates per level (default: 1)
  -r, --repeat <int>           Repeat count per party (default: 1)
  -p, --base-port <int>        Base port used by the first run (default: auto-pick)
  -o, --out-dir <path>         Output directory (default: run_logs/protocol_compare)
  -h, --help                   Show this help

Notes:
  - This script launches party IDs 0..n (inclusive), i.e. n computing parties + 1 helper.
  - It prints a summary table with:
      offline communication (MB), offline time (s),
      online communication (MB), online time (s)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -d|--chain-mul) CHAIN_MUL="$2"; shift 2 ;;
    -g|--gates-per-level) GATES_PER_LEVEL="$2"; shift 2 ;;
    -r|--repeat) REPEAT="$2"; shift 2 ;;
    -p|--base-port) BASE_PORT="$2"; shift 2 ;;
    -o|--out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

mkdir -p "${OUT_DIR}"

TOTAL_PARTIES=$((N + 1))
PORT_STRIDE="$(localhost_compute_port_stride "${TOTAL_PARTIES}" 64)"
TOTAL_PORT_WIDTH=$((4 * PORT_STRIDE))

if [[ -n "${BASE_PORT}" ]]; then
  localhost_ensure_base_port_available "${BASE_PORT}" "${TOTAL_PORT_WIDTH}"
else
  BASE_PORT="$(localhost_pick_free_base_port "${TOTAL_PORT_WIDTH}")"
fi

if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
fi
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target benchmarks >/dev/null

run_multiparty() {
  local tag="$1"
  local port="$2"
  shift 2
  local -a cmd=("$@")
  local run_dir="${OUT_DIR}/${tag}"
  echo "[RUN] tag=${tag}, chain_mul=${CHAIN_MUL}, repeat=${REPEAT}, port=${port}"
  localhost_run_multiparty_group "${run_dir}" "${N}" "${port}" "${PORT_STRIDE}" "${cmd[@]}" -r "${REPEAT}"
  echo "[DONE] tag=${tag}"
}

run_multiparty "asterisk_offline" "${BASE_PORT}" \
  "${BUILD_DIR}/benchmarks/asterisk_offline" -g "${GATES_PER_LEVEL}" -d "${CHAIN_MUL}"

run_multiparty "asterisk_online" "$((BASE_PORT + PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk_online" -g "${GATES_PER_LEVEL}" -d "${CHAIN_MUL}"

run_multiparty "asterisk2_semi_honest" "$((BASE_PORT + 2 * PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_mpc" -g "${GATES_PER_LEVEL}" -d "${CHAIN_MUL}" --security-model semi-honest

run_multiparty "asterisk2_malicious" "$((BASE_PORT + 3 * PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_mpc" -g "${GATES_PER_LEVEL}" -d "${CHAIN_MUL}" --security-model malicious

PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "Python interpreter not found. Please install python3." >&2
  exit 1
fi

"${PYTHON_BIN}" - "${OUT_DIR}" "${N}" <<'PY'
import json
import pathlib
import statistics
import sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
MB = 1024 * 1024

def load_party_jsons(tag):
    run_dir = out_dir / tag
    files = [run_dir / f"p{pid}.json" for pid in range(n + 1)]
    docs = []
    for p in files:
        text = p.read_text().strip()
        if not text:
            raise RuntimeError(f"Empty benchmark output: {p}")
        lines = [line for line in text.splitlines() if line.strip()]
        try:
            docs.append(json.loads(text))
        except json.JSONDecodeError:
            # Some benchmark binaries append one JSON document per run.
            docs.append(json.loads(lines[-1]))
    return docs

def summarize_split_mode(tag, bench_key_time="time"):
    # For asterisk_offline / asterisk_online style:
    # each row has "time"(ms) + "communication" array.
    party_data = load_party_jsons(tag)
    reps = len(party_data[0]["benchmarks"])
    rep_total_bytes = []
    rep_wall_ms = []
    for r in range(reps):
        bytes_sum = 0
        wall_ms = 0.0
        for pid in range(n + 1):
            row = party_data[pid]["benchmarks"][r]
            bytes_sum += sum(int(v) for v in row["communication"])
            wall_ms = max(wall_ms, float(row[bench_key_time]))
        rep_total_bytes.append(bytes_sum)
        rep_wall_ms.append(wall_ms)
    return {
        "comm_mb": statistics.mean(rep_total_bytes) / MB,
        "time_s": statistics.mean(rep_wall_ms) / 1000.0,
    }

def summarize_asterisk2_mode(tag):
    # rows have offline/online blocks and *_bytes helpers
    party_data = load_party_jsons(tag)
    reps = len(party_data[0]["benchmarks"])
    off_bytes, off_time_ms = [], []
    on_bytes, on_time_ms = [], []
    for r in range(reps):
        off_b = 0
        on_b = 0
        off_t = 0.0
        on_t = 0.0
        for pid in range(n + 1):
            row = party_data[pid]["benchmarks"][r]
            off_b += int(row["offline_bytes"])
            on_b += int(row["online_bytes"])
            off_t = max(off_t, float(row["offline"]["time"]))
            on_t = max(on_t, float(row["online"]["time"]))
        off_bytes.append(off_b)
        on_bytes.append(on_b)
        off_time_ms.append(off_t)
        on_time_ms.append(on_t)
    return {
        "offline_comm_mb": statistics.mean(off_bytes) / MB,
        "offline_time_s": statistics.mean(off_time_ms) / 1000.0,
        "online_comm_mb": statistics.mean(on_bytes) / MB,
        "online_time_s": statistics.mean(on_time_ms) / 1000.0,
    }

asterisk_off = summarize_split_mode("asterisk_offline")
asterisk_on = summarize_split_mode("asterisk_online")
a2_sh = summarize_asterisk2_mode("asterisk2_semi_honest")
a2_mal = summarize_asterisk2_mode("asterisk2_malicious")

rows = [
    ("Asterisk", asterisk_off["comm_mb"], asterisk_off["time_s"],
     asterisk_on["comm_mb"], asterisk_on["time_s"]),
    ("Asterisk2.0 semi-honest", a2_sh["offline_comm_mb"], a2_sh["offline_time_s"],
     a2_sh["online_comm_mb"], a2_sh["online_time_s"]),
    ("Asterisk2.0 malicious", a2_mal["offline_comm_mb"], a2_mal["offline_time_s"],
     a2_mal["online_comm_mb"], a2_mal["online_time_s"]),
]

print("\n=== Multiplication Protocol Comparison (avg over repeats, wall-clock=max over parties) ===")
print("| Protocol | Offline Comm (MB) | Offline Time (s) | Online Comm (MB) | Online Time (s) |")
print("|---|---:|---:|---:|---:|")
for name, oc, ot, ic, it in rows:
    print(f"| {name} | {oc:.6f} | {ot:.6f} | {ic:.6f} | {it:.6f} |")
PY

echo
echo "[DONE] Raw per-party JSON files are saved under: ${OUT_DIR}"
