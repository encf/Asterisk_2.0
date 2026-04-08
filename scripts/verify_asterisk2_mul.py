#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import sys

PRIME = 17816577890427308801


def run_cmd(cmd):
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def main():
    parser = argparse.ArgumentParser(description="Run Asterisk2.0 locally and verify multiplication output reconstruction.")
    parser.add_argument("--binary", default="./build/benchmarks/asterisk2_mpc", help="Path to asterisk2_mpc binary")
    parser.add_argument("--num-parties", "-n", type=int, default=3, help="Number of computing parties")
    parser.add_argument("--gates-per-level", "-g", type=int, default=1, help="Gates per level")
    parser.add_argument("--depth", "-d", type=int, default=10, help="Circuit depth")
    parser.add_argument("--repeat", "-r", type=int, default=1, help="Benchmark repeats")
    parser.add_argument("--port", type=int, default=10000, help="Base port")
    parser.add_argument("--out-dir", default="/tmp/asterisk2_mul_verify", help="Output directory for per-party JSON")
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    procs = []
    for pid in range(args.num_parties + 1):
        out_file = out_dir / f"p{pid}.json"
        cmd = [
            args.binary,
            "--localhost",
            "-n", str(args.num_parties),
            "-p", str(pid),
            "-g", str(args.gates_per_level),
            "-d", str(args.depth),
            "-r", str(args.repeat),
            "--security-model", "semi-honest",
            "--dump-output-shares",
            "-o", str(out_file),
            "--port", str(args.port),
        ]
        procs.append((pid, run_cmd(cmd)))

    failed = False
    for pid, p in procs:
        out, _ = p.communicate()
        if p.returncode != 0:
            failed = True
            print(f"[pid={pid}] process failed with code {p.returncode}")
            print(out)
    if failed:
        return 1

    compute_rows = []
    for pid in range(args.num_parties):
        data = json.loads((out_dir / f"p{pid}.json").read_text())
        rows = data.get("benchmarks", [])
        if not rows:
            print(f"missing benchmarks in pid={pid} output")
            return 1
        compute_rows.append(rows[0])

    shares_by_party = [row.get("local_output_shares") for row in compute_rows]
    if any(sh is None for sh in shares_by_party):
        print("local_output_shares missing; run binary with --dump-output-shares support")
        return 1

    output_len = len(shares_by_party[0])
    if any(len(sh) != output_len for sh in shares_by_party):
        print("inconsistent local output share length across parties")
        return 1

    reconstructed = []
    for idx in range(output_len):
        s = 0
        for party in range(args.num_parties):
            s = (s + int(shares_by_party[party][idx])) % PRIME
        reconstructed.append(s)

    # Given benchmark input assignment: party 0 provides 5 and others provide 0 on every input wire.
    # Clear input per wire is therefore 5; each multiplication depth squares the value.
    expected = pow(5, 2 ** args.depth, PRIME)
    ok = all(v == expected for v in reconstructed)

    print(f"reconstructed_outputs={reconstructed}")
    print(f"expected_output={expected}")
    print(f"match={ok}")
    print(f"artifacts={out_dir}")

    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
