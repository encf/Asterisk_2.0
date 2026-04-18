#!/usr/bin/env bash

# Shared localhost launcher for benchmark scripts.
# It centralizes port-range reservation, child startup/readiness checks,
# and process cleanup so individual compare scripts do not race each other
# or leave stale children behind on failure.

if [[ -n "${ASTERISK_LOCALHOST_RUNNER_SH:-}" ]]; then
  return 0
fi
ASTERISK_LOCALHOST_RUNNER_SH=1

: "${LOCALHOST_LAUNCHER_PORT_START:=30000}"
: "${LOCALHOST_LAUNCHER_PORT_END:=65000}"
: "${LOCALHOST_LAUNCHER_PORT_STEP:=16}"
: "${LOCALHOST_LAUNCHER_BIND_TIMEOUT:=15}"

LOCALHOST_LAUNCHER_PIDS=()
LOCALHOST_LAUNCHER_TRAP_INSTALLED=0

localhost_launcher_install_trap() {
  if [[ "${LOCALHOST_LAUNCHER_TRAP_INSTALLED}" -eq 0 ]]; then
    trap localhost_launcher_cleanup EXIT INT TERM
    LOCALHOST_LAUNCHER_TRAP_INSTALLED=1
  fi
}

localhost_launcher_cleanup() {
  local pid
  for pid in "${LOCALHOST_LAUNCHER_PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${LOCALHOST_LAUNCHER_PIDS[@]:-}"; do
    wait "${pid}" 2>/dev/null || true
  done
  LOCALHOST_LAUNCHER_PIDS=()
}

localhost_launcher_register_pid() {
  LOCALHOST_LAUNCHER_PIDS+=("$1")
}

localhost_launcher_unregister_pid() {
  local target="$1"
  local -a kept=()
  local pid
  for pid in "${LOCALHOST_LAUNCHER_PIDS[@]:-}"; do
    if [[ "${pid}" != "${target}" ]]; then
      kept+=("${pid}")
    fi
  done
  LOCALHOST_LAUNCHER_PIDS=("${kept[@]}")
}

localhost_compute_port_stride() {
  local total_parties="$1"
  local cushion="${2:-64}"
  python3 - "$total_parties" "$cushion" <<'PY'
import sys
n_total = int(sys.argv[1])
cushion = int(sys.argv[2])
print(2 * n_total * n_total + cushion)
PY
}

localhost_pick_free_base_port() {
  local width="$1"
  local start_port="${2:-${LOCALHOST_LAUNCHER_PORT_START}}"
  python3 - "$start_port" "$width" "${LOCALHOST_LAUNCHER_PORT_END}" "${LOCALHOST_LAUNCHER_PORT_STEP}" <<'PY'
import socket
import sys

start = int(sys.argv[1])
width = int(sys.argv[2])
end = int(sys.argv[3])
step = int(sys.argv[4])

def range_is_free(base):
    for port in range(base, base + width):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            s.close()
            return False
        s.close()
    return True

for base in range(max(1024, start), end - width + 1, step):
    if range_is_free(base):
        print(base)
        break
else:
    raise SystemExit(f"Could not find a free port range of width {width} starting from {start}")
PY
}

localhost_ensure_base_port_available() {
  local base_port="$1"
  local width="$2"
  python3 - "$base_port" "$width" <<'PY'
import socket
import sys

base = int(sys.argv[1])
width = int(sys.argv[2])
if base < 1024 or base + width - 1 > 65535:
    raise SystemExit(f"Invalid base port {base}: need a free range up to {base + width - 1} within 1024..65535")

for port in range(base, base + width):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as exc:
        s.close()
        raise SystemExit(f"Base port {base} is not usable: {exc}")
    s.close()
PY
}

localhost_pid_has_listener_in_range() {
  local child_pid="$1"
  local start_port="$2"
  local end_port="$3"
  python3 - "$child_pid" "$start_port" "$end_port" <<'PY'
import re
import subprocess
import sys

pid = int(sys.argv[1])
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

try:
    output = subprocess.check_output(["ss", "-H", "-ltnp"], text=True, stderr=subprocess.DEVNULL)
except subprocess.CalledProcessError:
    raise SystemExit(1)

for line in output.splitlines():
    if f"pid={pid}," not in line and f"pid={pid})" not in line:
        continue
    match = re.search(r":(\d+)\s", line)
    if not match:
        continue
    port = int(match.group(1))
    if start_port <= port <= end_port:
        raise SystemExit(0)

raise SystemExit(1)
PY
}

localhost_wait_for_bind() {
  local child_pid="$1"
  local party_id="$2"
  local start_port="$3"
  local end_port="$4"
  local log_file="$5"
  local ready_file="$6"
  local timeout_s="${7:-${LOCALHOST_LAUNCHER_BIND_TIMEOUT}}"
  local deadline=$((SECONDS + timeout_s))
  local marker="BOUND_OK pid=${party_id} port=${start_port}"
  local json_file
  json_file="$(dirname "${log_file}")/../p${party_id}.json"

  while (( SECONDS < deadline )); do
    if ! kill -0 "${child_pid}" 2>/dev/null; then
      if [[ -s "${json_file}" ]]; then
        printf 'pid=%s\njson=%s\nstatus=fast-exit\n' "${child_pid}" "${json_file}" > "${ready_file}"
        echo "[READY] party=${party_id}, pid=${child_pid}, mode=fast-exit"
        return 0
      fi
      echo "[ERROR] party ${party_id} exited before binding any port in ${start_port}-${end_port}" >&2
      if [[ -f "${log_file}" ]]; then
        echo "[ERROR] Last log lines from ${log_file}:" >&2
        tail -n 20 "${log_file}" >&2 || true
      fi
      return 1
    fi
    if [[ -f "${log_file}" ]] && grep -q "${marker}" "${log_file}"; then
      printf 'pid=%s\nport_range=%s-%s\nmarker=%s\n' "${child_pid}" "${start_port}" "${end_port}" "${marker}" > "${ready_file}"
      echo "[READY] party=${party_id}, pid=${child_pid}, marker=${marker}"
      return 0
    fi
    if localhost_pid_has_listener_in_range "${child_pid}" "${start_port}" "${end_port}"; then
      printf 'pid=%s\nport_range=%s-%s\n' "${child_pid}" "${start_port}" "${end_port}" > "${ready_file}"
      echo "[READY] party=${party_id}, pid=${child_pid}, ports=${start_port}-${end_port}"
      return 0
    fi
    sleep 0.1
  done

  echo "[ERROR] party ${party_id} did not expose a listening socket in ${start_port}-${end_port} within ${timeout_s}s" >&2
  if [[ -f "${log_file}" ]]; then
    echo "[ERROR] Last log lines from ${log_file}:" >&2
    tail -n 20 "${log_file}" >&2 || true
  fi
  return 1
}

localhost_kill_jobs() {
  local -a jobs=("$@")
  local pid
  for pid in "${jobs[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${jobs[@]}"; do
    wait "${pid}" 2>/dev/null || true
    localhost_launcher_unregister_pid "${pid}"
  done
}

localhost_wait_for_jobs() {
  local -a jobs=("$@")
  local idx
  for idx in "${!jobs[@]}"; do
    local pid="${jobs[$idx]}"
    if ! wait "${pid}"; then
      local status=$?
      local j
      for j in "${!jobs[@]}"; do
        if (( j > idx )); then
          kill "${jobs[$j]}" 2>/dev/null || true
        fi
      done
      for j in "${!jobs[@]}"; do
        if (( j > idx )); then
          wait "${jobs[$j]}" 2>/dev/null || true
        fi
      done
      for pid in "${jobs[@]}"; do
        localhost_launcher_unregister_pid "${pid}"
      done
      return "${status}"
    fi
  done
  for pid in "${jobs[@]}"; do
    localhost_launcher_unregister_pid "${pid}"
  done
}

localhost_run_multiparty_group() {
  local run_dir="$1"
  local n="$2"
  local base_port="$3"
  local port_width="$4"
  shift 4
  local -a cmd=("$@")
  local log_dir="${run_dir}/logs"
  local ready_dir="${run_dir}/ready"
  local -a jobs=()
  local pid child out_json out_log ready_file

  rm -rf "${run_dir}"
  mkdir -p "${log_dir}" "${ready_dir}"

  localhost_launcher_install_trap

  for pid in $(seq 0 "${n}"); do
    out_json="${run_dir}/p${pid}.json"
    out_log="${log_dir}/p${pid}.log"
    "${cmd[@]}" --localhost -n "${n}" -p "${pid}" --port "${base_port}" -o "${out_json}" >"${out_log}" 2>&1 &
    child=$!
    jobs+=("${child}")
    localhost_launcher_register_pid "${child}"
  done

  for pid in $(seq 0 "${n}"); do
    ready_file="${ready_dir}/p${pid}.ready"
    if ! localhost_wait_for_bind "${jobs[$pid]}" "${pid}" "${base_port}" "$((base_port + port_width - 1))" "${log_dir}/p${pid}.log" "${ready_file}"; then
      localhost_kill_jobs "${jobs[@]}"
      return 1
    fi
  done

  localhost_wait_for_jobs "${jobs[@]}"
}
