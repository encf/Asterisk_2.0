#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

N=5
FIXED_MUL_COUNT=1000
FRAC_BITS=8
ELL_X=40
SLACK=8
BASE_PORT=52000
OUT_DIR="${ROOT_DIR}/run_logs/fixedpoint_mul_compare"

usage() {
  cat <<'EOF'
Usage: scripts/compare_fixedpoint_mul_a2.sh [options]

Compare Asterisk2.0 fixed-point multiplication
  (one integer multiplication + one truncation) across:
  - semi-honest
  - malicious

Options:
  -n, --num-parties <int>       Number of computing parties (default: 5)
  -c, --fixed-mul-count <int>   Number of fixed-point multiplications (default: 1000)
  --frac-bits <int>             Fractional bits m for truncation (default: 8)
  --ell-x <int>                 Truncation ell_x (default: 40)
  --slack <int>                 Truncation slack s (default: 8)
  -p, --base-port <int>         Base port (default: 52000)
  -o, --out-dir <path>          Output directory (default: run_logs/fixedpoint_mul_compare)
  -h, --help                    Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -c|--fixed-mul-count) FIXED_MUL_COUNT="$2"; shift 2 ;;
    --frac-bits) FRAC_BITS="$2"; shift 2 ;;
    --ell-x) ELL_X="$2"; shift 2 ;;
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
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target asterisk2_mpc >/dev/null

run_model() {
  local model="$1"
  local port="$2"
  local run_dir="${OUT_DIR}/${model}"
  local log_dir="${run_dir}/logs"
  rm -rf "${run_dir}"
  mkdir -p "${run_dir}"
  mkdir -p "${log_dir}"
  local -a jobs=()
  for pid in $(seq 0 "${N}"); do
    "${BUILD_DIR}/benchmarks/asterisk2_mpc" --localhost -n "${N}" -p "${pid}" \
      -g 1 -d 1 -r "${FIXED_MUL_COUNT}" --port "${port}" \
      --security-model "${model}" \
      --trunc-frac-bits "${FRAC_BITS}" --trunc-lx "${ELL_X}" --trunc-slack "${SLACK}" \
      -o "${run_dir}/p${pid}.json" >"${log_dir}/p${pid}.log" 2>&1 &
    jobs+=("$!")
  done
  for j in "${jobs[@]}"; do wait "${j}"; done
}

run_model semi-honest "${BASE_PORT}"
run_model malicious "$((BASE_PORT + 200))"

PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "Python interpreter not found. Please install python3." >&2
  exit 1
fi

"${PYTHON_BIN}" - "${OUT_DIR}" "${N}" <<'PY'
import json, pathlib, statistics, sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
MB = 1024 * 1024

def load_model(model):
    return [json.loads((out_dir / model / f"p{pid}.json").read_text()) for pid in range(n + 1)]

def summarize(model):
    parties = load_model(model)
    reps = len(parties[0]["benchmarks"])
    off_comm = []
    off_time = []
    on_comm = []
    on_time = []
    for r in range(reps):
      # one fixed-point multiplication := mul + truncation
      off_b = 0
      on_b = 0
      off_t_ms = 0.0
      on_t_ms = 0.0
      for pid in range(n + 1):
        row = parties[pid]["benchmarks"][r]
        off_b += int(row["offline_bytes"]) + int(row["truncation_offline_bytes"])
        on_b += int(row["online_bytes"]) + int(row["truncation_bytes"])
        off_t_ms = max(off_t_ms, float(row["offline"]["time"]) + float(row["truncation_offline"]["time"]))
        on_t_ms = max(on_t_ms, float(row["online"]["time"]) + float(row["truncation"]["time"]))
      off_comm.append(off_b / MB)
      on_comm.append(on_b / MB)
      off_time.append(off_t_ms / 1000.0)
      on_time.append(on_t_ms / 1000.0)
    return statistics.mean(off_comm), statistics.mean(off_time), statistics.mean(on_comm), statistics.mean(on_time)

sh = summarize("semi-honest")
mal = summarize("malicious")

print("\n=== Asterisk2.0 Fixed-Point Multiplication (mul + trunc) ===")
print("| Security Model | Offline Comm (MB) | Offline Time (s) | Online Comm (MB) | Online Time (s) |")
print("|---|---:|---:|---:|---:|")
print(f"| semi-honest | {sh[0]:.6f} | {sh[1]:.6f} | {sh[2]:.6f} | {sh[3]:.6f} |")
print(f"| malicious | {mal[0]:.6f} | {mal[1]:.6f} | {mal[2]:.6f} | {mal[3]:.6f} |")
PY

echo
echo "[DONE] Raw JSON written to: ${OUT_DIR}"
