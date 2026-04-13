#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

N=3
COMPARE_COUNT=10
LX=16
SLACK=8
BASE_PORT=41000
OUT_DIR="${ROOT_DIR}/run_logs/compare_protocols"

usage() {
  cat <<'EOF'
Usage: scripts/compare_cmp_protocols.sh [options]

Compare protocol benchmark (offline/online comm+time) across:
  1) Asterisk (legacy baseline via asterisk_offline + asterisk_online)
  2) Asterisk2.0 semi-honest compare (BGTEZ)
  3) Asterisk2.0 malicious compare

Options:
  -n, --num-parties <int>    Number of computing parties (default: 3)
  -c, --compare-count <int>  Number of comparisons (default: 10)
  --lx <int>                 BGTEZ lx parameter (default: 16)
  --slack <int>              BGTEZ slack parameter s (default: 8)
  -p, --base-port <int>      Base port for first run (default: 41000)
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
    -o|--out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

mkdir -p "${OUT_DIR}"

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache >/dev/null
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target benchmarks >/dev/null

run_multiparty() {
  local tag="$1"
  local port="$2"
  shift 2
  local -a cmd=("$@")
  local run_dir="${OUT_DIR}/${tag}"
  rm -rf "${run_dir}"
  mkdir -p "${run_dir}"
  local -a jobs=()
  for pid in $(seq 0 "${N}"); do
    "${cmd[@]}" --localhost -n "${N}" -p "${pid}" --port "${port}" -o "${run_dir}/p${pid}.json" \
      >/tmp/"${tag}_p${pid}".log 2>&1 &
    jobs+=("$!")
  done
  for j in "${jobs[@]}"; do wait "${j}"; done
}

# Asterisk baseline: use compare_count as depth surrogate.
run_multiparty "asterisk_offline" "${BASE_PORT}" \
  "${BUILD_DIR}/benchmarks/asterisk_offline" -g 1 -d "${COMPARE_COUNT}" -r 1
run_multiparty "asterisk_online" "$((BASE_PORT + 200))" \
  "${BUILD_DIR}/benchmarks/asterisk_online" -g 1 -d "${COMPARE_COUNT}" -r 1

# Asterisk2 BGTEZ compare: compare_count comparisons via repeat.
run_multiparty "asterisk2_bgtez_sh" "$((BASE_PORT + 400))" \
  "${BUILD_DIR}/benchmarks/asterisk2_bgtez" --security-model semi-honest \
  --lx "${LX}" --slack "${SLACK}" --x-clear 123 -r "${COMPARE_COUNT}"
run_multiparty "asterisk2_bgtez_mal" "$((BASE_PORT + 600))" \
  "${BUILD_DIR}/benchmarks/asterisk2_bgtez" --security-model malicious \
  --lx "${LX}" --slack "${SLACK}" --x-clear 123 -r "${COMPARE_COUNT}"

python - "${OUT_DIR}" "${N}" <<'PY'
import json, pathlib, statistics, sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
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

print("\n=== Compare Protocol Benchmark Summary ===")
print("| Protocol | Offline Comm (MB) | Offline Time (s) | Online Comm (MB) | Online Time (s) |")
print("|---|---:|---:|---:|---:|")
print(f"| Asterisk (baseline) | {a_off_c:.6f} | {a_off_t:.6f} | {a_on_c:.6f} | {a_on_t:.6f} |")
print(f"| Asterisk2.0 semi-honest (BGTEZ) | {sh[0]:.6f} | {sh[1]:.6f} | {sh[2]:.6f} | {sh[3]:.6f} |")
print(f"| Asterisk2.0 malicious (BGTEZ) | {mal[0]:.6f} | {mal[1]:.6f} | {mal[2]:.6f} | {mal[3]:.6f} |")
PY

echo
echo "[DONE] Raw JSON written to: ${OUT_DIR}"
