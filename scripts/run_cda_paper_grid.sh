#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_SCRIPT="${ROOT_DIR}/scripts/run_cda_tc.sh"
OUT_DIR="${ROOT_DIR}/run_logs/cda_paper_grid"

BANDWIDTH="100mbit"
DELAYS_MS=(20 50)
PARTIES=(5 10 16)
BUY_SIZE=32
SELL_SIZE=32
NEW_ORDER_NAME=1
NEW_ORDER_UNIT=1
NEW_ORDER_PRICE=1
LX=16
SLACK=8
REPEAT=1
THREADS=6
SECURITY_PARAM=128
SKIP_TC=0

usage() {
  cat <<'EOF'
Usage: scripts/run_cda_paper_grid.sh [options]

Run the paper's CDA experiment grid on localhost loopback:
  - one-way delay: 20ms, 50ms
  - participants: 5, 10, 16
  - M = N = 32

Options:
  --bandwidth <rate>            tc rate, e.g. 100mbit (default: 100mbit)
  -b, --buy-size <int>          Buy list size M (default: 32)
  -s, --sell-size <int>         Sell list size N (default: 32)
  --new-order-name <int>        Deterministic new-order name input (default: 1)
  --new-order-unit <int>        Deterministic new-order unit input (default: 1)
  --new-order-price <int>       Deterministic new-order price input (default: 1)
  --lx <int>                    Asterisk2.0 comparison lx parameter (default: 16)
  --slack <int>                 Asterisk2.0 comparison slack parameter s (default: 8)
  -r, --repeat <int>            Repetitions per case (default: 1)
  --threads <int>               Legacy Asterisk thread count (default: 6)
  --security-param <int>        Legacy Asterisk security parameter (default: 128)
  --out-dir <path>              Output directory (default: run_logs/cda_paper_grid)
  --skip-tc                     Do not configure tc; run each case on the current local network
  -h, --help                    Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bandwidth) BANDWIDTH="$2"; shift 2 ;;
    -b|--buy-size) BUY_SIZE="$2"; shift 2 ;;
    -s|--sell-size) SELL_SIZE="$2"; shift 2 ;;
    --new-order-name) NEW_ORDER_NAME="$2"; shift 2 ;;
    --new-order-unit) NEW_ORDER_UNIT="$2"; shift 2 ;;
    --new-order-price) NEW_ORDER_PRICE="$2"; shift 2 ;;
    --lx) LX="$2"; shift 2 ;;
    --slack) SLACK="$2"; shift 2 ;;
    -r|--repeat) REPEAT="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --security-param) SECURITY_PARAM="$2"; shift 2 ;;
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

echo "=== CDA paper grid ==="
echo "bandwidth=${BANDWIDTH}"
echo "buy_size=${BUY_SIZE}"
echo "sell_size=${SELL_SIZE}"
echo "new_order_name=${NEW_ORDER_NAME}"
echo "new_order_unit=${NEW_ORDER_UNIT}"
echo "new_order_price=${NEW_ORDER_PRICE}"
echo "repeat=${REPEAT}"
echo "threads=${THREADS}"
echo "security_param=${SECURITY_PARAM}"
echo "lx=${LX}"
echo "slack=${SLACK}"
echo "skip_tc=${SKIP_TC}"
echo "delays=${DELAYS_MS[*]}"
echo "parties=${PARTIES[*]}"
echo

for delay_ms in "${DELAYS_MS[@]}"; do
  for n in "${PARTIES[@]}"; do
    label="cda_owd${delay_ms}ms_n${n}"
    echo "=== Running case: ${label} ==="
    cmd=(
      "${RUN_SCRIPT}"
      --delay "${delay_ms}"
      --bandwidth "${BANDWIDTH}"
      -n "${n}"
      -b "${BUY_SIZE}"
      -s "${SELL_SIZE}"
      --new-order-name "${NEW_ORDER_NAME}"
      --new-order-unit "${NEW_ORDER_UNIT}"
      --new-order-price "${NEW_ORDER_PRICE}"
      --lx "${LX}"
      --slack "${SLACK}"
      -r "${REPEAT}"
      --threads "${THREADS}"
      --security-param "${SECURITY_PARAM}"
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

echo "[DONE] Paper-grid CDA results saved under: ${OUT_DIR}"
