#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

N=3
BATCH_SIZE=1000
SINGLE_REPEAT=5
BATCH_REPEAT=1
FRAC_BITS=8
ELL_X=40
SLACK=8
BASE_PORT=""
LABEL=""
OUT_DIR="${ROOT_DIR}/run_logs/truncation_compare"

usage() {
  cat <<'EOF'
Usage: scripts/compare_truncation_a2.sh [options]

Benchmark standalone Asterisk2.0 probabilistic truncation across:
  - semi-honest
  - malicious

The script assumes your desired tc/netem rules are already active.
It does not modify the network configuration.

Measurements:
  1) single truncation latency      (g=1, d=0)
  2) batched truncation benchmark   (g=batch-size, d=0)

Options:
  -n, --num-parties <int>       Number of computing parties (default: 3)
  -b, --batch-size <int>        Number of truncations in the batch benchmark (default: 1000)
  --single-repeat <int>         Repetitions for the single-latency case (default: 5)
  --batch-repeat <int>          Repetitions for the batched case (default: 1)
  -r, --repeat <int>            Set both single-repeat and batch-repeat to the same value
  --frac-bits <int>             Fractional bits m for truncation (default: 8)
  --ell-x <int>                 Truncation ell_x (default: 40)
  --slack <int>                 Truncation slack s (default: 8)
  -p, --base-port <int>         Base port (default: auto-pick a free range)
  --label <text>                Optional scenario label for the summary output
  -o, --out-dir <path>          Output directory (default: run_logs/truncation_compare)
  -h, --help                    Show help
EOF
}

compute_case_port_stride() {
  local total_parties=$1
  python3 - "$total_parties" <<'PY'
import sys
n_total = int(sys.argv[1])
# NetIOMP uses ports up to:
#   base + 2 * (i * nP + j) + 1
# for the pair (i, j), so we reserve a full square plus a small cushion.
print(2 * n_total * n_total + 32)
PY
}

pick_free_base_port() {
  local total_parties=$1
  local width=$2
  python3 - "$total_parties" "$width" <<'PY'
import socket
import sys

START = 20000
END = 65000
WIDTH = int(sys.argv[2])
# Search more densely than WIDTH-sized jumps. Otherwise one occupied port inside
# each probed block can make us miss many valid ranges on long-running hosts.
STRIDE = 16

def range_is_free(base):
    sockets = []
    try:
        for port in range(base, base + WIDTH):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # NetIO listens on 0.0.0.0, so probe the same bind scope here.
            s.bind(("0.0.0.0", port))
            sockets.append(s)
        return True
    except OSError:
        return False
    finally:
        for s in sockets:
            s.close()

for base in range(START, END - WIDTH + 1, STRIDE):
    if range_is_free(base):
        print(base)
        break
else:
    raise SystemExit("Could not find a free port range for truncation benchmark")
PY
}

ensure_base_port_available() {
  local base_port="$1"
  local width="$2"
  python3 - "$base_port" "$width" <<'PY'
import socket
import sys

base = int(sys.argv[1])
width = int(sys.argv[2])
if base < 1024 or base + width - 1 > 65535:
    raise SystemExit(f"Invalid base port {base}: need a free range up to {base + width - 1} within 1024..65535")

sockets = []
try:
    for port in range(base, base + width):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        sockets.append(s)
except OSError as exc:
    raise SystemExit(f"Base port {base} is not usable: {exc}")
finally:
    for s in sockets:
        s.close()
PY
}

wait_for_jobs() {
  local -a jobs=("$@")
  local remaining=${#jobs[@]}
  while (( remaining > 0 )); do
    if wait -n; then
      remaining=$((remaining - 1))
    else
      local status=$?
      for pid in "${jobs[@]}"; do
        kill "${pid}" 2>/dev/null || true
      done
      wait "${jobs[@]}" 2>/dev/null || true
      return "${status}"
    fi
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -b|--batch-size) BATCH_SIZE="$2"; shift 2 ;;
    --single-repeat) SINGLE_REPEAT="$2"; shift 2 ;;
    --batch-repeat) BATCH_REPEAT="$2"; shift 2 ;;
    -r|--repeat)
      SINGLE_REPEAT="$2"
      BATCH_REPEAT="$2"
      shift 2
      ;;
    --frac-bits) FRAC_BITS="$2"; shift 2 ;;
    --ell-x) ELL_X="$2"; shift 2 ;;
    --slack) SLACK="$2"; shift 2 ;;
    -p|--base-port) BASE_PORT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    -o|--out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

mkdir -p "${OUT_DIR}"
TOTAL_PARTIES=$((N + 1))
CASE_PORT_STRIDE="$(compute_case_port_stride "${TOTAL_PARTIES}")"
TOTAL_PORT_WIDTH=$((4 * CASE_PORT_STRIDE))

if [[ -z "${BASE_PORT}" ]]; then
  BASE_PORT="$(pick_free_base_port "${TOTAL_PARTIES}" "${TOTAL_PORT_WIDTH}")"
else
  ensure_base_port_available "${BASE_PORT}" "${TOTAL_PORT_WIDTH}"
fi

if [[ ! -x "${BUILD_DIR}/benchmarks/asterisk2_mpc" ]]; then
  echo "Missing benchmark binary: ${BUILD_DIR}/benchmarks/asterisk2_mpc" >&2
  echo "Please build it first, for example:" >&2
  echo "  cmake -S \"${ROOT_DIR}\" -B \"${BUILD_DIR}\" -DCMAKE_BUILD_TYPE=Release" >&2
  echo "  cmake --build \"${BUILD_DIR}\" -j\$(nproc) --target asterisk2_mpc" >&2
  exit 1
fi

run_case() {
  local model="$1"
  local case_tag="$2"
  local gates="$3"
  local repeat="$4"
  local port="$5"
  local run_dir="${OUT_DIR}/${model}/${case_tag}"
  local log_dir="${run_dir}/logs"
  echo "[RUN] model=${model}, case=${case_tag}, gates=${gates}, repeat=${repeat}, port=${port}"
  rm -rf "${run_dir}"
  mkdir -p "${log_dir}"
  local -a jobs=()

  for pid in $(seq 0 "${N}"); do
    "${BUILD_DIR}/benchmarks/asterisk2_mpc" --localhost -n "${N}" -p "${pid}" \
      -g "${gates}" -d 0 -r "${repeat}" --port "${port}" \
      --security-model "${model}" \
      --trunc-frac-bits "${FRAC_BITS}" --trunc-lx "${ELL_X}" --trunc-slack "${SLACK}" \
      --dump-output-shares \
      -o "${run_dir}/p${pid}.json" >"${log_dir}/p${pid}.log" 2>&1 &
    jobs+=("$!")
  done

  wait_for_jobs "${jobs[@]}"
  echo "[DONE] model=${model}, case=${case_tag}"
}

run_model() {
  local model="$1"
  local port_base="$2"
  run_case "${model}" single 1 "${SINGLE_REPEAT}" "${port_base}"
  run_case "${model}" batch "${BATCH_SIZE}" "${BATCH_REPEAT}" "$((port_base + CASE_PORT_STRIDE))"
}

run_model semi-honest "${BASE_PORT}"
run_model malicious "$((BASE_PORT + 2 * CASE_PORT_STRIDE))"

python3 - "${OUT_DIR}" "${N}" "${BATCH_SIZE}" "${LABEL}" "${ELL_X}" "${FRAC_BITS}" "${SLACK}" "${SINGLE_REPEAT}" "${BATCH_REPEAT}" <<'PY'
import json
import pathlib
import statistics
import sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
batch_size = int(sys.argv[3])
label = sys.argv[4]
ell_x = int(sys.argv[5])
frac_bits = int(sys.argv[6])
slack = int(sys.argv[7])
single_repeat = int(sys.argv[8])
batch_repeat = int(sys.argv[9])
MB = 1024 * 1024

def load_case(model, case_tag):
    return [json.loads((out_dir / model / case_tag / f"p{pid}.json").read_text()) for pid in range(n + 1)]

def summarize_case(model, case_tag):
    parties = load_case(model, case_tag)
    reps = len(parties[0]["benchmarks"])
    off_comm_mb = []
    off_time_s = []
    on_comm_mb = []
    on_time_s = []
    max_party_on_comm_mb = []
    for r in range(reps):
        off_bytes = 0
        on_bytes = 0
        off_ms = 0.0
        on_ms = 0.0
        max_party_on_bytes = 0
        for pid in range(n + 1):
            row = parties[pid]["benchmarks"][r]
            off_bytes += int(row["truncation_offline_bytes"])
            on_bytes += int(row["truncation_bytes"])
            off_ms = max(off_ms, float(row["truncation_offline"]["time"]))
            on_ms = max(on_ms, float(row["truncation"]["time"]))
            if pid < n:
                max_party_on_bytes = max(max_party_on_bytes, int(row["truncation_bytes"]))
        off_comm_mb.append(off_bytes / MB)
        off_time_s.append(off_ms / 1000.0)
        on_comm_mb.append(on_bytes / MB)
        on_time_s.append(on_ms / 1000.0)
        max_party_on_comm_mb.append(max_party_on_bytes / MB)
    return {
        "offline_comm_mb": statistics.mean(off_comm_mb),
        "offline_time_s": statistics.mean(off_time_s),
        "online_comm_mb": statistics.mean(on_comm_mb),
        "online_time_s": statistics.mean(on_time_s),
        "max_party_online_comm_mb": statistics.mean(max_party_on_comm_mb),
    }

single_sh = summarize_case("semi-honest", "single")
single_mal = summarize_case("malicious", "single")
batch_sh = summarize_case("semi-honest", "batch")
batch_mal = summarize_case("malicious", "batch")

summary = {
    "label": label,
    "num_parties": n,
    "batch_size": batch_size,
    "parameters": {
        "ell_x": ell_x,
        "frac_bits": frac_bits,
        "slack": slack,
        "single_repeat": single_repeat,
        "batch_repeat": batch_repeat,
        "benchmark_input_model": "party0=5, other parties=0 (fixed in asterisk2_mpc)",
    },
    "semi_honest": {
        "single_latency_ms": single_sh["online_time_s"] * 1000.0,
        "batch": batch_sh,
    },
    "malicious": {
        "single_latency_ms": single_mal["online_time_s"] * 1000.0,
        "batch": batch_mal,
    },
}

(out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

title = "=== Asterisk2.0 Standalone Truncation Summary ==="
if label:
    title += f" [{label}]"
print("\n" + title)
print("| Security Model | Single Latency (ms) | Batch Size | Offline Comm (MB) | Offline Time (s) | Online Comm (MB) | Max Per-Party Online Comm (MB) | Online Time (s) |")
print("|---|---:|---:|---:|---:|---:|---:|---:|")
print(f"| semi-honest | {single_sh['online_time_s'] * 1000.0:.6f} | {batch_size} | {batch_sh['offline_comm_mb']:.6f} | {batch_sh['offline_time_s']:.6f} | {batch_sh['online_comm_mb']:.6f} | {batch_sh['max_party_online_comm_mb']:.6f} | {batch_sh['online_time_s']:.6f} |")
print(f"| malicious | {single_mal['online_time_s'] * 1000.0:.6f} | {batch_size} | {batch_mal['offline_comm_mb']:.6f} | {batch_mal['offline_time_s']:.6f} | {batch_mal['online_comm_mb']:.6f} | {batch_mal['max_party_online_comm_mb']:.6f} | {batch_mal['online_time_s']:.6f} |")
print("\n[INFO] Single latency uses the `single` case; all communication/time columns refer to the batched case.")
print(f"[INFO] Machine-readable summary: {out_dir / 'summary.json'}")
PY

echo
echo "[DONE] Raw JSON written to: ${OUT_DIR}"
