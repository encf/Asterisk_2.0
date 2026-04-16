#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_SCRIPT="${ROOT_DIR}/scripts/run_truncation_tc.sh"
OUT_DIR="${ROOT_DIR}/run_logs/truncation_paper_grid"

BANDWIDTH="100mbit"
DELAYS_MS=(20 50)
PARTIES=(5 10 16)
BATCH_SIZE=1000
SINGLE_REPEAT=5
BATCH_REPEAT=1

usage() {
  cat <<'EOF'
Usage: scripts/run_truncation_paper_grid.sh [options]

Run the paper's standalone truncation experiment grid on localhost loopback:
  - one-way delay: 20ms, 50ms
  - participants: 5, 10, 16

For each case, the script configures tc on `lo`, runs the truncation benchmark,
and stores outputs under run_logs/truncation_paper_grid/.

Options:
  --bandwidth <rate>            tc rate, e.g. 100mbit (default: 100mbit)
  -b, --batch-size <int>        Batch truncation size (default: 1000)
  --single-repeat <int>         Repetitions for single latency (default: 5)
  --batch-repeat <int>          Repetitions for batched case (default: 1)
  --out-dir <path>              Output directory (default: run_logs/truncation_paper_grid)
  -h, --help                    Show help

Example:
  ./scripts/run_truncation_paper_grid.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bandwidth) BANDWIDTH="$2"; shift 2 ;;
    -b|--batch-size) BATCH_SIZE="$2"; shift 2 ;;
    --single-repeat) SINGLE_REPEAT="$2"; shift 2 ;;
    --batch-repeat) BATCH_REPEAT="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -x "${RUN_SCRIPT}" ]]; then
  echo "Expected executable wrapper script at ${RUN_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "=== Truncation paper grid ==="
echo "bandwidth=${BANDWIDTH}"
echo "batch_size=${BATCH_SIZE}"
echo "single_repeat=${SINGLE_REPEAT}"
echo "batch_repeat=${BATCH_REPEAT}"
echo "delays=${DELAYS_MS[*]}"
echo "parties=${PARTIES[*]}"
echo

for delay_ms in "${DELAYS_MS[@]}"; do
  for n in "${PARTIES[@]}"; do
    label="owd${delay_ms}ms_n${n}"
    echo "=== Running case: ${label} ==="
    "${RUN_SCRIPT}" \
      --delay "${delay_ms}" \
      --bandwidth "${BANDWIDTH}" \
      -n "${n}" \
      -b "${BATCH_SIZE}" \
      --single-repeat "${SINGLE_REPEAT}" \
      --batch-repeat "${BATCH_REPEAT}" \
      --label "${label}" \
      --out-dir "${OUT_DIR}"
    echo
  done
done

echo "[DONE] Paper-grid truncation results saved under: ${OUT_DIR}"
