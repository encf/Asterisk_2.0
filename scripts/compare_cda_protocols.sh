#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
source "${ROOT_DIR}/scripts/lib_localhost_runner.sh"

N=5
BUY_SIZE=50
SELL_SIZE=50
NEW_ORDER_NAME=1
NEW_ORDER_UNIT=1
NEW_ORDER_PRICE=1
LX=16
SLACK=8
REPEAT=1
THREADS=6
SECURITY_PARAM=128
BASE_PORT=""
LABEL=""
OUT_DIR="${ROOT_DIR}/run_logs/cda_protocols"

usage() {
  cat <<'EOF'
Usage: scripts/compare_cda_protocols.sh [options]

Compare Dark Pool CDA benchmark across:
  1) Asterisk (legacy baseline)
  2) Asterisk2.0 semi-honest
  3) Asterisk2.0 malicious

Options:
  -n, --num-parties <int>      Number of computing parties (default: 5)
  -b, --buy-size <int>         Buy list size M (default: 50)
  -s, --sell-size <int>        Sell list size N (default: 50)
  --new-order-name <int>       Deterministic new-order name input (default: 1)
  --new-order-unit <int>       Deterministic new-order unit input (default: 1)
  --new-order-price <int>      Deterministic new-order price input (default: 1)
  --lx <int>                   Comparison lx parameter for Asterisk2.0 (default: 16)
  --slack <int>                Comparison slack parameter s (default: 8)
  -r, --repeat <int>           Repetitions per case (default: 1)
  --threads <int>              Legacy Asterisk thread count (default: 6)
  --security-param <int>       Legacy Asterisk security parameter (default: 128)
  -p, --base-port <int>        Base port for the first run (default: auto-pick)
  --label <text>               Optional scenario label
  -o, --out-dir <path>         Output directory (default: run_logs/cda_protocols)
  -h, --help                   Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
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
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target Darkpool_CDA asterisk2_darkpool_cda >/dev/null

TOTAL_PARTIES=$((N + 1))
PORT_STRIDE="$(localhost_compute_port_stride "${TOTAL_PARTIES}" 64)"
TOTAL_PORT_WIDTH=$((3 * PORT_STRIDE))
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
  echo "[RUN] tag=${tag}, n=${N}, buy=${BUY_SIZE}, sell=${SELL_SIZE}, repeat=${REPEAT}, port=${port}"
  localhost_run_multiparty_group "${run_dir}" "${N}" "${port}" "${PORT_STRIDE}" "${cmd[@]}"
  echo "[DONE] tag=${tag}"
}

run_multiparty "asterisk_cda" "${BASE_PORT}" \
  "${BUILD_DIR}/benchmarks/Darkpool_CDA" \
  -b "${BUY_SIZE}" -s "${SELL_SIZE}" -r "${REPEAT}" \
  --new-order-name "${NEW_ORDER_NAME}" \
  --new-order-unit "${NEW_ORDER_UNIT}" \
  --new-order-price "${NEW_ORDER_PRICE}" \
  --threads "${THREADS}" --security-param "${SECURITY_PARAM}"
run_multiparty "asterisk2_cda_sh" "$((BASE_PORT + PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_darkpool_cda" \
  -b "${BUY_SIZE}" -s "${SELL_SIZE}" -r "${REPEAT}" \
  --security-model semi-honest --lx "${LX}" --slack "${SLACK}" \
  --new-order-name "${NEW_ORDER_NAME}" \
  --new-order-unit "${NEW_ORDER_UNIT}" \
  --new-order-price "${NEW_ORDER_PRICE}"
run_multiparty "asterisk2_cda_dh" "$((BASE_PORT + 2 * PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_darkpool_cda" \
  -b "${BUY_SIZE}" -s "${SELL_SIZE}" -r "${REPEAT}" \
  --security-model malicious --lx "${LX}" --slack "${SLACK}" \
  --new-order-name "${NEW_ORDER_NAME}" \
  --new-order-unit "${NEW_ORDER_UNIT}" \
  --new-order-price "${NEW_ORDER_PRICE}"

python3 - "${RUN_OUT_DIR}" "${N}" "${LABEL}" "${BUY_SIZE}" "${SELL_SIZE}" "${NEW_ORDER_NAME}" "${NEW_ORDER_UNIT}" "${NEW_ORDER_PRICE}" "${LX}" "${SLACK}" "${REPEAT}" <<'PY'
import json
import pathlib
import statistics
import sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
label = sys.argv[3]
buy_size = int(sys.argv[4])
sell_size = int(sys.argv[5])
new_order_name = int(sys.argv[6])
new_order_unit = int(sys.argv[7])
new_order_price = int(sys.argv[8])
lx = int(sys.argv[9])
slack = int(sys.argv[10])
repeat = int(sys.argv[11])
MB = 1024 * 1024

def read_rows(tag):
    parties = [json.loads((out_dir / tag / f"p{pid}.json").read_text()) for pid in range(n + 1)]
    reps = len(parties[0]["benchmarks"])
    return parties, reps

def summarize_split(tag):
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
    return {
        "offline_comm_mb": statistics.mean(off_comm),
        "offline_time_s": statistics.mean(off_time),
        "online_comm_mb": statistics.mean(on_comm),
        "online_time_s": statistics.mean(on_time),
    }

effective_label = label if label else out_dir.name

summary = {
    "label": effective_label,
    "num_parties": n,
    "buy_list_size": buy_size,
    "sell_list_size": sell_size,
    "new_order_name": new_order_name,
    "new_order_unit": new_order_unit,
    "new_order_price": new_order_price,
    "repeat": repeat,
    "parameters": {"lx": lx, "slack": slack},
    "asterisk": summarize_split("asterisk_cda"),
    "asterisk2_sh": summarize_split("asterisk2_cda_sh"),
    "asterisk2_dh": summarize_split("asterisk2_cda_dh"),
}

(out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

md = [
    f"=== CDA Benchmark Summary === [{effective_label}]",
    "| Protocol | Offline Comm (MB) | Offline Time (s) | Online Comm (MB) | Online Time (s) |",
    "|---|---:|---:|---:|---:|",
]

rows = [
    ("Asterisk", summary["asterisk"]),
    ("Asterisk2.0 semi-honest", summary["asterisk2_sh"]),
    ("Asterisk2.0 malicious", summary["asterisk2_dh"]),
]
for name, row in rows:
    md.append(
        f"| {name} | {row['offline_comm_mb']:.6f} | {row['offline_time_s']:.6f} | "
        f"{row['online_comm_mb']:.6f} | {row['online_time_s']:.6f} |"
    )

md.append("")
md.append(f"[INFO] Parameters: n={n}, buy_size={buy_size}, sell_size={sell_size}, repeat={repeat}, lx={lx}, slack={slack}")
md.append(f"[INFO] New order inputs: name={new_order_name}, unit={new_order_unit}, price={new_order_price}")
md.append(f"[INFO] Machine-readable summary: {out_dir / 'summary.json'}")

summary_md = "\n".join(md) + "\n"
(out_dir / "summary.md").write_text(summary_md)
print(summary_md, end="")
PY
