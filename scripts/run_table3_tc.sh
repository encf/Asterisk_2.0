#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPARE_SCRIPT="${ROOT_DIR}/scripts/compare_mul_protocols.sh"
OUT_DIR="${ROOT_DIR}/run_logs/table3_tc"
source "${ROOT_DIR}/scripts/lib_localhost_runner.sh"

BANDWIDTH="100mbit"
CHAIN_MUL=10000
REPEAT=1
BASE_PORT=30000
PING_COUNT=5
CLEAR_TC_ON_EXIT=1

PARTIES=(5 10 16)
ONE_WAY_DELAYS_MS=(20 50)

usage() {
  cat <<'EOF'
Usage: scripts/run_table3_tc.sh [options]

Run the full Table III multiplication experiment on loopback (`lo`) with `tc`.
The script:
  1) applies symmetric one-way delay + bandwidth shaping on `lo`
  2) runs Asterisk / Asterisk2.0 multiplication benchmarks
  3) saves raw logs, `tc` state, `ping` output, and a Table III style summary

Default experiment grid:
  - bandwidth: 100mbit
  - one-way delay: 20ms, 50ms
  - participants: 5, 10, 16
  - chain multiplications: 10000

Options:
  --bandwidth <rate>        tc rate, e.g. 100mbit (default: 100mbit)
  --delays <list>           comma-separated one-way delays in ms (default: 20,50)
  --parties <list>          comma-separated participant counts (default: 5,10,16)
  --chain-mul <int>         number of dependent multiplications (default: 10000)
  --repeat <int>            benchmark repeat count passed to compare_mul_protocols.sh (default: 1)
  --base-port <int>         base port for the first condition (default: 30000)
  --ping-count <int>        ping probes used to snapshot RTT after tc setup (default: 5)
  --out-dir <path>          output directory (default: run_logs/table3_tc)
  --keep-tc                 keep the final tc rule instead of clearing it on exit
  -h, --help                show this help

Examples:
  scripts/run_table3_tc.sh
  scripts/run_table3_tc.sh --repeat 3
  scripts/run_table3_tc.sh --delays 20,50 --parties 5,10,16
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

csv_to_array() {
  local raw="$1"
  local -n out_ref="$2"
  IFS=',' read -r -a out_ref <<<"$raw"
}

clear_tc() {
  sudo tc qdisc del dev lo root 2>/dev/null || true
}

set_tc() {
  local delay_ms="$1"
  clear_tc
  sudo tc qdisc add dev lo root netem delay "${delay_ms}ms" rate "${BANDWIDTH}"
}

show_tc() {
  tc qdisc show dev lo
}

measure_ping_avg_ms() {
  local log_file="$1"
  ping -n -c "${PING_COUNT}" 127.0.0.1 | tee "${log_file}" >/dev/null
  python3 - "${log_file}" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/", text)
print(match.group(2) if match else "NA")
PY
}

cleanup() {
  if [[ "${CLEAR_TC_ON_EXIT}" -eq 1 ]]; then
    clear_tc
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bandwidth) BANDWIDTH="$2"; shift 2 ;;
    --delays)
      csv_to_array "$2" ONE_WAY_DELAYS_MS
      shift 2
      ;;
    --parties)
      csv_to_array "$2" PARTIES
      shift 2
      ;;
    --chain-mul) CHAIN_MUL="$2"; shift 2 ;;
    --repeat) REPEAT="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --ping-count) PING_COUNT="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --keep-tc) CLEAR_TC_ON_EXIT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

require_cmd sudo
require_cmd tc
require_cmd ping
require_cmd python3

if [[ ! -x "${COMPARE_SCRIPT}" ]]; then
  echo "Expected executable compare script at ${COMPARE_SCRIPT}" >&2
  exit 1
fi

validate_port_plan() {
  local start_port="$1"
  shift
  local -a parties=("$@")
  local current="$start_port"
  local last_used=0
  local n
  for n in "${parties[@]}"; do
    local total_parties=$((n + 1))
    local stride
    stride="$(localhost_compute_port_stride "${total_parties}" 64)"
    last_used=$((current + 4 * stride - 1))
    current=$((current + 4 * stride))
  done
  local num_envs=${#ONE_WAY_DELAYS_MS[@]}
  last_used=$((start_port + (last_used - start_port + 1) * num_envs - 1))
  if (( start_port < 1024 || last_used > 65535 )); then
    echo "Invalid --base-port=${start_port}: this table run needs ports up to ${last_used}, which must stay within 1024..65535." >&2
    exit 1
  fi
}

validate_port_plan "${BASE_PORT}" "${PARTIES[@]}"

mkdir -p "${OUT_DIR}"
SUMMARY_CSV="${OUT_DIR}/table3_summary.csv"
SUMMARY_MD="${OUT_DIR}/table3_summary.md"

trap cleanup EXIT

sudo -v

cat >"${SUMMARY_CSV}" <<'EOF'
one_way_delay_ms,rtt_ms,bandwidth,num_parties,protocol,offline_comm_mb,offline_time_s,online_comm_mb,online_time_s,end_to_end_time_s
EOF

current_port="${BASE_PORT}"

for delay_ms in "${ONE_WAY_DELAYS_MS[@]}"; do
  delay_ms="${delay_ms%ms}"
  env_tag="bw_${BANDWIDTH}_owd_${delay_ms}ms"
  env_dir="${OUT_DIR}/${env_tag}"
  mkdir -p "${env_dir}"

  echo "=== Configuring lo: bandwidth=${BANDWIDTH}, one-way delay=${delay_ms}ms ==="
  set_tc "${delay_ms}"
  show_tc | tee "${env_dir}/tc_qdisc.txt"

  ping_avg_ms="$(measure_ping_avg_ms "${env_dir}/ping.txt")"
  {
    echo "bandwidth=${BANDWIDTH}"
    echo "one_way_delay_ms=${delay_ms}"
    echo "approx_rtt_ms=$((delay_ms * 2))"
    echo "measured_ping_avg_ms=${ping_avg_ms}"
  } > "${env_dir}/env.txt"

  for n in "${PARTIES[@]}"; do
    condition_dir="${env_dir}/n${n}"
    raw_dir="${condition_dir}/raw"
    mkdir -p "${condition_dir}"
    total_parties=$((n + 1))
    port_stride="$(localhost_compute_port_stride "${total_parties}" 64)"
    port_width=$((4 * port_stride))
    condition_base_port="$(localhost_pick_free_base_port "${port_width}" "${current_port}")"

    echo "--- Running n=${n} at one-way delay ${delay_ms}ms (approx RTT $((delay_ms * 2))ms), base_port=${condition_base_port} ---"
    "${COMPARE_SCRIPT}" \
      -n "${n}" \
      -d "${CHAIN_MUL}" \
      -g 1 \
      -r "${REPEAT}" \
      -p "${condition_base_port}" \
      -o "${raw_dir}" | tee "${condition_dir}/compare_output.txt"

    python3 - "${raw_dir}" "${n}" "${delay_ms}" "${BANDWIDTH}" "${SUMMARY_CSV}" <<'PY'
import json
import pathlib
import statistics
import sys

raw_dir = pathlib.Path(sys.argv[1])
n = int(sys.argv[2])
delay_ms = int(sys.argv[3])
bandwidth = sys.argv[4]
summary_csv = pathlib.Path(sys.argv[5])
MB = 1024 * 1024

def load_party_jsons(tag):
    run_dir = raw_dir / tag
    docs = []
    for pid in range(n + 1):
        text = (run_dir / f"p{pid}.json").read_text().strip()
        if not text:
            raise RuntimeError(f"Empty benchmark output: {run_dir / f'p{pid}.json'}")
        lines = [line for line in text.splitlines() if line.strip()]
        try:
            docs.append(json.loads(text))
        except json.JSONDecodeError:
            docs.append(json.loads(lines[-1]))
    return docs

def summarize_split_mode(tag):
    party_data = load_party_jsons(tag)
    reps = len(party_data[0]["benchmarks"])
    rep_total_bytes = []
    rep_wall_ms = []
    for r in range(reps):
        bytes_sum = 0
        wall_ms = 0.0
        for pid in range(n + 1):
            row = party_data[pid]["benchmarks"][r]
            bytes_sum += sum(int(v) for v in row["communication"])
            wall_ms = max(wall_ms, float(row["time"]))
        rep_total_bytes.append(bytes_sum)
        rep_wall_ms.append(wall_ms)
    return {
        "offline_comm_mb": statistics.mean(rep_total_bytes) / MB,
        "offline_time_s": statistics.mean(rep_wall_ms) / 1000.0,
    }

def summarize_asterisk2_mode(tag):
    party_data = load_party_jsons(tag)
    reps = len(party_data[0]["benchmarks"])
    off_bytes, off_time_ms = [], []
    on_bytes, on_time_ms = [], []
    for r in range(reps):
        off_b = 0
        on_b = 0
        off_t = 0.0
        on_t = 0.0
        for pid in range(n + 1):
            row = party_data[pid]["benchmarks"][r]
            off_b += int(row["offline_bytes"])
            on_b += int(row["online_bytes"])
            off_t = max(off_t, float(row["offline"]["time"]))
            on_t = max(on_t, float(row["online"]["time"]))
        off_bytes.append(off_b)
        on_bytes.append(on_b)
        off_time_ms.append(off_t)
        on_time_ms.append(on_t)
    return {
        "offline_comm_mb": statistics.mean(off_bytes) / MB,
        "offline_time_s": statistics.mean(off_time_ms) / 1000.0,
        "online_comm_mb": statistics.mean(on_bytes) / MB,
        "online_time_s": statistics.mean(on_time_ms) / 1000.0,
    }

asterisk_off = summarize_split_mode("asterisk_offline")
asterisk_on = summarize_split_mode("asterisk_online")
a2_sh = summarize_asterisk2_mode("asterisk2_semi_honest")
a2_mal = summarize_asterisk2_mode("asterisk2_malicious")

rows = [
    (
        "Asterisk-DH",
        asterisk_off["offline_comm_mb"],
        asterisk_off["offline_time_s"],
        asterisk_on["offline_comm_mb"],
        asterisk_on["offline_time_s"],
        asterisk_off["offline_time_s"] + asterisk_on["offline_time_s"],
    ),
    (
        "Asterisk 2.0-SH",
        a2_sh["offline_comm_mb"],
        a2_sh["offline_time_s"],
        a2_sh["online_comm_mb"],
        a2_sh["online_time_s"],
        a2_sh["offline_time_s"] + a2_sh["online_time_s"],
    ),
    (
        "Asterisk 2.0-DH",
        a2_mal["offline_comm_mb"],
        a2_mal["offline_time_s"],
        a2_mal["online_comm_mb"],
        a2_mal["online_time_s"],
        a2_mal["offline_time_s"] + a2_mal["online_time_s"],
    ),
]

with summary_csv.open("a", encoding="utf-8") as f:
    for protocol, off_c, off_t, on_c, on_t, e2e in rows:
        f.write(
            f"{delay_ms},{delay_ms * 2},{bandwidth},{n},{protocol},"
            f"{off_c:.9f},{off_t:.9f},{on_c:.9f},{on_t:.9f},{e2e:.9f}\n"
        )
PY

    current_port=$((condition_base_port + port_width))
  done
done

python3 - "${SUMMARY_CSV}" "${SUMMARY_MD}" <<'PY'
import csv
import pathlib
import sys
from collections import defaultdict

csv_path = pathlib.Path(sys.argv[1])
md_path = pathlib.Path(sys.argv[2])

rows = list(csv.DictReader(csv_path.open()))
grouped = defaultdict(dict)
for row in rows:
    key = (int(row["one_way_delay_ms"]), int(row["num_parties"]))
    grouped[key][row["protocol"]] = row

delays = sorted({int(r["one_way_delay_ms"]) for r in rows})
parties = sorted({int(r["num_parties"]) for r in rows})

lines = []
lines.append("# Table III Summary")
lines.append("")
lines.append("Dependent integer multiplication under loopback `tc` shaping.")
lines.append("")

for delay in delays:
    rtt = delay * 2
    lines.append(f"## 100mbit, one-way delay {delay} ms (approx RTT {rtt} ms)")
    lines.append("")
    lines.append("| n | Asterisk-DH Off Comm (MB) | Asterisk-DH Off Time (s) | Asterisk-DH On Comm (MB) | Asterisk-DH On Time (s) | Ours-SH Off Comm (MB) | Ours-SH Off Time (s) | Ours-SH On Comm (MB) | Ours-SH On Time (s) | Ours-DH Off Comm (MB) | Ours-DH Off Time (s) | Ours-DH On Comm (MB) | Ours-DH On Time (s) |")
    lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for n in parties:
      data = grouped[(delay, n)]
      a = data["Asterisk-DH"]
      sh = data["Asterisk 2.0-SH"]
      dh = data["Asterisk 2.0-DH"]
      lines.append(
          "| {n} | {a_off_c:.3f} | {a_off_t:.3f} | {a_on_c:.3f} | {a_on_t:.3f} | "
          "{sh_off_c:.3f} | {sh_off_t:.3f} | {sh_on_c:.3f} | {sh_on_t:.3f} | "
          "{dh_off_c:.3f} | {dh_off_t:.3f} | {dh_on_c:.3f} | {dh_on_t:.3f} |".format(
              n=n,
              a_off_c=float(a["offline_comm_mb"]),
              a_off_t=float(a["offline_time_s"]),
              a_on_c=float(a["online_comm_mb"]),
              a_on_t=float(a["online_time_s"]),
              sh_off_c=float(sh["offline_comm_mb"]),
              sh_off_t=float(sh["offline_time_s"]),
              sh_on_c=float(sh["online_comm_mb"]),
              sh_on_t=float(sh["online_time_s"]),
              dh_off_c=float(dh["offline_comm_mb"]),
              dh_off_t=float(dh["offline_time_s"]),
              dh_on_c=float(dh["online_comm_mb"]),
              dh_on_t=float(dh["online_time_s"]),
          )
      )
    lines.append("")

md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

echo
echo "[DONE] Table III experiment finished."
echo "Raw outputs: ${OUT_DIR}"
echo "CSV summary: ${SUMMARY_CSV}"
echo "Markdown summary: ${SUMMARY_MD}"
