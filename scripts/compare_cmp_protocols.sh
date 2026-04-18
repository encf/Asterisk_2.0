#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
source "${ROOT_DIR}/scripts/lib_localhost_runner.sh"

N=5
COMPARE_COUNT=1
LX=16
SLACK=8
BASE_PORT=""
LABEL=""
OUT_DIR="${ROOT_DIR}/run_logs/compare_protocols"

usage() {
  cat <<'EOF'
Usage: scripts/compare_cmp_protocols.sh [options]

Compare protocol benchmark (offline/online comm+time) across:
  1) Asterisk (legacy baseline via asterisk_offline + asterisk_online)
  2) Asterisk2.0 semi-honest compare (BGTEZ)
  3) Asterisk2.0 malicious compare

Options:
  -n, --num-parties <int>    Number of computing parties (default: 5)
  -c, --compare-count <int>  Number of comparisons (default: 1)
  --lx <int>                 BGTEZ lx parameter (default: 16)
  --slack <int>              BGTEZ slack parameter s (default: 8)
  -p, --base-port <int>      Base port for the first run (default: auto-pick)
  --label <text>             Optional scenario label for the summary output
  -o, --out-dir <path>       Output directory (default: run_logs/compare_protocols)
  -h, --help                 Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -c|--compare-count) COMPARE_COUNT="$2"; shift 2 ;;
    --lx) LX="$2"; shift 2 ;;
    --slack) SLACK="$2"; shift 2 ;;
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
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target benchmarks >/dev/null

TOTAL_PARTIES=$((N + 1))
PORT_STRIDE="$(localhost_compute_port_stride "${TOTAL_PARTIES}" 64)"
TOTAL_PORT_WIDTH=$((4 * PORT_STRIDE))

if [[ -n "${BASE_PORT}" ]]; then
  localhost_ensure_base_port_available "${BASE_PORT}" "${TOTAL_PORT_WIDTH}"
else
  BASE_PORT="$(localhost_pick_free_base_port "${TOTAL_PORT_WIDTH}")"
fi

run_multiparty() {
  local tag="$1"
  local port="$2"
  shift 2
  local -a cmd=("$@")
  local run_dir="${RUN_OUT_DIR}/${tag}"
  echo "[RUN] tag=${tag}, compare_count=${COMPARE_COUNT}, port=${port}"
  localhost_run_multiparty_group "${run_dir}" "${N}" "${port}" "${PORT_STRIDE}" "${cmd[@]}"
  echo "[DONE] tag=${tag}"
}

run_multiparty "asterisk_offline" "${BASE_PORT}" \
  "${BUILD_DIR}/benchmarks/asterisk_cmp_offline" -c "${COMPARE_COUNT}" -r 1
run_multiparty "asterisk_online" "$((BASE_PORT + PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk_cmp_online" -c "${COMPARE_COUNT}" -r 1
run_multiparty "asterisk2_bgtez_sh" "$((BASE_PORT + 2 * PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_bgtez" --security-model semi-honest \
  --lx "${LX}" --slack "${SLACK}" --x-clear 123 -r "${COMPARE_COUNT}"
run_multiparty "asterisk2_bgtez_mal" "$((BASE_PORT + 3 * PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_bgtez" --security-model malicious \
  --lx "${LX}" --slack "${SLACK}" --x-clear 123 -r "${COMPARE_COUNT}"

python3 - "${RUN_OUT_DIR}" "${N}" "${COMPARE_COUNT}" "${LABEL}" "${LX}" "${SLACK}" <<'PY'
import json
import pathlib
import statistics
import sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
compare_count = int(sys.argv[3])
label = sys.argv[4]
lx = int(sys.argv[5])
slack = int(sys.argv[6])
MB = 1024 * 1024

def read_rows(tag):
    parties = [json.loads((out_dir / tag / f"p{pid}.json").read_text()) for pid in range(n + 1)]
    reps = len(parties[0]["benchmarks"])
    return parties, reps

def summarize_asterisk_split(tag):
    parties, reps = read_rows(tag)
    comm, time_s = [], []
    for r in range(reps):
        bytes_sum = 0
        wall_ms = 0.0
        for pid in range(n + 1):
            row = parties[pid]["benchmarks"][r]
            bytes_sum += sum(int(v) for v in row["communication"])
            wall_ms = max(wall_ms, float(row["time"]))
        comm.append(bytes_sum / MB)
        time_s.append(wall_ms / 1000.0)
    return statistics.mean(comm), statistics.mean(time_s)

def summarize_bgtez(tag):
    parties, reps = read_rows(tag)
    off_comm, off_time, on_comm, on_time = [], [], [], []
    for r in range(reps):
        off_b = on_b = 0
        off_ms = on_ms = 0.0
        for pid in range(n + 1):
            row = parties[pid]["benchmarks"][r]
            off_b += int(row["offline_bytes"])
            on_b += int(row["online_bytes"])
            off_ms = max(off_ms, float(row["offline"]["time"]))
            on_ms = max(on_ms, float(row["online"]["time"]))
        off_comm.append(off_b / MB)
        on_comm.append(on_b / MB)
        off_time.append(off_ms / 1000.0)
        on_time.append(on_ms / 1000.0)
    return statistics.mean(off_comm), statistics.mean(off_time), statistics.mean(on_comm), statistics.mean(on_time)

a_off_c, a_off_t = summarize_asterisk_split("asterisk_offline")
a_on_c, a_on_t = summarize_asterisk_split("asterisk_online")
sh = summarize_bgtez("asterisk2_bgtez_sh")
mal = summarize_bgtez("asterisk2_bgtez_mal")

summary = {
    "label": label,
    "num_parties": n,
    "compare_count": compare_count,
    "parameters": {
        "lx": lx,
        "slack": slack,
        "x_clear": 123,
    },
    "asterisk_baseline": {
        "offline_comm_mb": a_off_c,
        "offline_time_s": a_off_t,
        "online_comm_mb": a_on_c,
        "online_time_s": a_on_t,
    },
    "asterisk2_semi_honest": {
        "offline_comm_mb": sh[0],
        "offline_time_s": sh[1],
        "online_comm_mb": sh[2],
        "online_time_s": sh[3],
    },
    "asterisk2_malicious": {
        "offline_comm_mb": mal[0],
        "offline_time_s": mal[1],
        "online_comm_mb": mal[2],
        "online_time_s": mal[3],
    },
}

(out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

title = "=== Compare Protocol Benchmark Summary ==="
if label:
    title += f" [{label}]"
print("\n" + title)
print("| Protocol | Offline Comm (MB) | Offline Time (s) | Online Comm (MB) | Online Time (s) |")
print("|---|---:|---:|---:|---:|")
print(f"| Asterisk (baseline) | {a_off_c:.6f} | {a_off_t:.6f} | {a_on_c:.6f} | {a_on_t:.6f} |")
print(f"| Asterisk2.0 semi-honest (BGTEZ) | {sh[0]:.6f} | {sh[1]:.6f} | {sh[2]:.6f} | {sh[3]:.6f} |")
print(f"| Asterisk2.0 malicious (BGTEZ) | {mal[0]:.6f} | {mal[1]:.6f} | {mal[2]:.6f} | {mal[3]:.6f} |")
print(f"\n[INFO] Machine-readable summary: {out_dir / 'summary.json'}")
PY

echo
echo "[DONE] Raw JSON written to: ${RUN_OUT_DIR}"
