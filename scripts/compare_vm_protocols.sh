#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
source "${ROOT_DIR}/scripts/lib_localhost_runner.sh"

N=5
BUY_SIZE=32
SELL_SIZE=32
FILL_VALUE=1
LX=16
SLACK=8
REPEAT=1
THREADS=6
SECURITY_PARAM=128
BASE_PORT=""
LABEL=""
OUT_DIR="${ROOT_DIR}/run_logs/vm_protocols"

usage() {
  cat <<'EOF'
Usage: scripts/compare_vm_protocols.sh [options]

Compare Dark Pool VM benchmark across:
  1) Asterisk (legacy baseline)
  2) Asterisk2.0 semi-honest
  3) Asterisk2.0 malicious

Options:
  -n, --num-parties <int>      Number of computing parties (default: 5)
  -b, --buy-size <int>         Buy list size M (default: 32)
  -s, --sell-size <int>        Sell list size N (default: 32)
  --fill-value <int>           Deterministic value for every unit input (default: 1)
  --lx <int>                   Comparison lx parameter for Asterisk2.0 (default: 16)
  --slack <int>                Comparison slack parameter s (default: 8)
  -r, --repeat <int>           Repetitions per case (default: 1)
  --threads <int>              Legacy Asterisk thread count (default: 6)
  --security-param <int>       Legacy Asterisk security parameter (default: 128)
  -p, --base-port <int>        Base port for the first run (default: auto-pick)
  --label <text>               Optional scenario label
  -o, --out-dir <path>         Output directory (default: run_logs/vm_protocols)
  -h, --help                   Show help
EOF
}

repeat_csv() {
  local value="$1"
  local count="$2"
  python3 - "$value" "$count" <<'PY'
import sys
value = sys.argv[1]
count = int(sys.argv[2])
print(",".join([value] * count))
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-parties) N="$2"; shift 2 ;;
    -b|--buy-size) BUY_SIZE="$2"; shift 2 ;;
    -s|--sell-size) SELL_SIZE="$2"; shift 2 ;;
    --fill-value) FILL_VALUE="$2"; shift 2 ;;
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
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target Darkpool_VM asterisk2_darkpool_vm >/dev/null

TOTAL_PARTIES=$((N + 1))
PORT_STRIDE="$(localhost_compute_port_stride "${TOTAL_PARTIES}" 64)"
TOTAL_PORT_WIDTH=$((3 * PORT_STRIDE))
if [[ -n "${BASE_PORT}" ]]; then
  localhost_ensure_base_port_available "${BASE_PORT}" "${TOTAL_PORT_WIDTH}"
else
  BASE_PORT="$(localhost_pick_free_base_port "${TOTAL_PORT_WIDTH}")"
fi

SELL_UNITS="$(repeat_csv "${FILL_VALUE}" "${SELL_SIZE}")"
BUY_UNITS="$(repeat_csv "${FILL_VALUE}" "${BUY_SIZE}")"

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

run_multiparty "asterisk_vm" "${BASE_PORT}" \
  "${BUILD_DIR}/benchmarks/Darkpool_VM" \
  -b "${BUY_SIZE}" -s "${SELL_SIZE}" -r "${REPEAT}" \
  --fill-value "${FILL_VALUE}" --threads "${THREADS}" --security-param "${SECURITY_PARAM}"
run_multiparty "asterisk2_vm_sh" "$((BASE_PORT + PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_darkpool_vm" \
  -b "${BUY_SIZE}" -s "${SELL_SIZE}" -r "${REPEAT}" \
  --security-model semi-honest --lx "${LX}" --slack "${SLACK}" \
  --sell-units "${SELL_UNITS}" --buy-units "${BUY_UNITS}"
run_multiparty "asterisk2_vm_dh" "$((BASE_PORT + 2 * PORT_STRIDE))" \
  "${BUILD_DIR}/benchmarks/asterisk2_darkpool_vm" \
  -b "${BUY_SIZE}" -s "${SELL_SIZE}" -r "${REPEAT}" \
  --security-model malicious --lx "${LX}" --slack "${SLACK}" \
  --sell-units "${SELL_UNITS}" --buy-units "${BUY_UNITS}"

python3 - "${RUN_OUT_DIR}" "${N}" "${LABEL}" "${BUY_SIZE}" "${SELL_SIZE}" "${FILL_VALUE}" "${LX}" "${SLACK}" "${REPEAT}" <<'PY'
import json
import pathlib
import statistics
import sys

out_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
label = sys.argv[3]
buy_size = int(sys.argv[4])
sell_size = int(sys.argv[5])
fill_value = int(sys.argv[6])
lx = int(sys.argv[7])
slack = int(sys.argv[8])
repeat = int(sys.argv[9])
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

summary = {
    "label": label,
    "num_parties": n,
    "buy_list_size": buy_size,
    "sell_list_size": sell_size,
    "fill_value": fill_value,
    "repeat": repeat,
    "parameters": {"lx": lx, "slack": slack},
    "asterisk": summarize_split("asterisk_vm"),
    "asterisk2_sh": summarize_split("asterisk2_vm_sh"),
    "asterisk2_dh": summarize_split("asterisk2_vm_dh"),
}

(out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

md = [
    f"=== VM Benchmark Summary === [{label}]",
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
md.append(f"[INFO] Parameters: n={n}, N=M={sell_size}, fill_value={fill_value}, repeat={repeat}, lx={lx}, slack={slack}")
md.append(f"[INFO] Machine-readable summary: {out_dir / 'summary.json'}")

summary_md = "\n".join(md) + "\n"
(out_dir / "summary.md").write_text(summary_md)
print(summary_md, end="")
PY
