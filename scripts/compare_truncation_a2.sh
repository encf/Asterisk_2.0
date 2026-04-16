#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

N=3
BATCH_SIZE=1000
REPEAT=5
FRAC_BITS=8
ELL_X=40
SLACK=8
BASE_PORT=54000
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
  -r, --repeat <int>            Number of repetitions per benchmark case (default: 5)
  --frac-bits <int>             Fractional bits m for truncation (default: 8)
  --ell-x <int>                 Truncation ell_x (default: 40)
  --slack <int>                 Truncation slack s (default: 8)
  -p, --base-port <int>         Base port (default: 54000)
  --label <text>                Optional scenario label for the summary output
  -o, --out-dir <path>          Output directory (default: run_logs/truncation_compare)
  -h, --help                    Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -b|--batch-size) BATCH_SIZE="$2"; shift 2 ;;
    -r|--repeat) REPEAT="$2"; shift 2 ;;
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

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache >/dev/null
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target asterisk2_mpc >/dev/null

run_case() {
  local model="$1"
  local case_tag="$2"
  local gates="$3"
  local repeat="$4"
  local port="$5"
  local run_dir="${OUT_DIR}/${model}/${case_tag}"
  rm -rf "${run_dir}"
  mkdir -p "${run_dir}"
  local -a jobs=()

  for pid in $(seq 0 "${N}"); do
    "${BUILD_DIR}/benchmarks/asterisk2_mpc" --localhost -n "${N}" -p "${pid}" \
      -g "${gates}" -d 0 -r "${repeat}" --port "${port}" \
      --security-model "${model}" \
      --trunc-frac-bits "${FRAC_BITS}" --trunc-lx "${ELL_X}" --trunc-slack "${SLACK}" \
      --dump-output-shares \
      -o "${run_dir}/p${pid}.json" >/tmp/"trunc_${model}_${case_tag}_p${pid}".log 2>&1 &
    jobs+=("$!")
  done

  for j in "${jobs[@]}"; do
    wait "${j}"
  done
}

run_model() {
  local model="$1"
  local port_base="$2"
  run_case "${model}" single 1 "${REPEAT}" "${port_base}"
  run_case "${model}" batch "${BATCH_SIZE}" "${REPEAT}" "$((port_base + 100))"
}

run_model semi-honest "${BASE_PORT}"
run_model malicious "$((BASE_PORT + 300))"

python - "${OUT_DIR}" "${N}" "${BATCH_SIZE}" "${LABEL}" "${ELL_X}" "${FRAC_BITS}" "${SLACK}" <<'PY'
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
