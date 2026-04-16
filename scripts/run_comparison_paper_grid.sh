#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_SCRIPT="${ROOT_DIR}/scripts/run_comparison_tc.sh"
OUT_DIR="${ROOT_DIR}/run_logs/comparison_paper_grid"

BANDWIDTH="100mbit"
DELAYS_MS=(20 50)
PARTIES=(5 10 16)
COMPARE_COUNT=1
LX=16
SLACK=8
SKIP_TC=0

usage() {
  cat <<'EOF'
Usage: scripts/run_comparison_paper_grid.sh [options]

Run the paper's comparison experiment grid on localhost loopback:
  - one-way delay: 20ms, 50ms
  - participants: 5, 10, 16

Options:
  --bandwidth <rate>            tc rate, e.g. 100mbit (default: 100mbit)
  -c, --compare-count <int>     Number of comparisons (default: 1)
  --lx <int>                    BGTEZ lx parameter (default: 16)
  --slack <int>                 BGTEZ slack parameter s (default: 8)
  --out-dir <path>              Output directory (default: run_logs/comparison_paper_grid)
  --skip-tc                     Do not configure tc; run each case on the current local network
  -h, --help                    Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bandwidth) BANDWIDTH="$2"; shift 2 ;;
    -c|--compare-count) COMPARE_COUNT="$2"; shift 2 ;;
    --lx) LX="$2"; shift 2 ;;
    --slack) SLACK="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --skip-tc) SKIP_TC=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -x "${RUN_SCRIPT}" ]]; then
  echo "Expected executable wrapper script at ${RUN_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "=== Comparison paper grid ==="
echo "bandwidth=${BANDWIDTH}"
echo "compare_count=${COMPARE_COUNT}"
echo "lx=${LX}"
echo "slack=${SLACK}"
echo "skip_tc=${SKIP_TC}"
echo "delays=${DELAYS_MS[*]}"
echo "parties=${PARTIES[*]}"
echo

for delay_ms in "${DELAYS_MS[@]}"; do
  for n in "${PARTIES[@]}"; do
    label="cmp_owd${delay_ms}ms_n${n}"
    echo "=== Running case: ${label} ==="
    cmd=(
      "${RUN_SCRIPT}"
      --delay "${delay_ms}"
      --bandwidth "${BANDWIDTH}"
      -n "${n}"
      -c "${COMPARE_COUNT}"
      --lx "${LX}"
      --slack "${SLACK}"
      --label "${label}"
      --out-dir "${OUT_DIR}"
    )
    if [[ "${SKIP_TC}" -eq 1 ]]; then
      cmd+=(--skip-tc)
    fi
    "${cmd[@]}"
    echo
  done
done

echo "[DONE] Paper-grid comparison results saved under: ${OUT_DIR}"
