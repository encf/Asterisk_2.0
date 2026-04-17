# Asterisk 2.0: Artifact for “Asterisk 2.0: Low-Latency MPC with a Friend via Optimistic Execution”

This repository implements the paper's semi-honest and malicious MPF protocols, including comparison, equality testing, probabilistic truncation, and dark-pool benchmarks.

For faithful localhost reproduction, set the number of computing parties \(n\) to be at most the number of available processor threads on the host. Otherwise, local scheduling contention can dominate the measured latency and distort the paper-style results.

## Mapping to the paper

- `src/Asterisk2.0/`: core protocol implementation of Asterisk 2.0.
- `benchmark/asterisk2_mpc.cpp`: multiplication and truncation benchmark entry point.
- `benchmark/asterisk2_bgtez.cpp`: comparison benchmark entry point.
- `benchmark/asterisk2_eqz.cpp`: equality benchmark entry point.
- `benchmark/asterisk2_darkpool_vm.cpp` and `benchmark/asterisk2_darkpool_cda.cpp`: application-level dark-pool benchmarks.
- `scripts/run_*_paper_grid.sh`: batch scripts used to sweep paper-style experiment settings.

## Quick start

1. Install dependencies.

```sh
./scripts/install_deps_ubuntu.sh
```

2. Build benchmarks.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)" --target benchmarks
```

3. Run one sanity check.

```sh
./build/benchmarks/asterisk2_mpc --help
```

## Paper result reproduction map

### Table II: integer multiplication

- Script: `scripts/run_table3_tc.sh` (paper grid) or `scripts/compare_mul_protocols.sh` (single condition)
- Minimal command:

```sh
sudo bash ./scripts/run_table3_tc.sh --out-dir run_logs/test_mul_paper
```

- Output directory: `run_logs/test_mul_paper/`
- Key output files:
  - `run_logs/test_mul_paper/table3_summary.csv`
  - `run_logs/test_mul_paper/table3_summary.md`
  - `run_logs/test_mul_paper/bw_100mbit_owd_20ms/n5/compare_output.txt`
  - `run_logs/test_mul_paper/bw_100mbit_owd_50ms/n16/compare_output.txt`
- Notes: this command directly runs the paper's integer-multiplication experiment grid, namely Net-L / Net-H, `n=5,10,16`, and 10,000 dependent multiplications. Per-party execution logs are written under each run directory's `logs/` subdirectory.

### Table IV: comparison

- Script: `scripts/run_comparison_paper_grid.sh` (paper grid) or `scripts/compare_cmp_protocols.sh` (single condition)
- Minimal command:

```sh
sudo ./scripts/run_comparison_paper_grid.sh --out-dir run_logs/test_cmp_paper
```

- Output directory: `run_logs/test_cmp_paper/`
- Key output files:
  - `run_logs/test_cmp_paper/cmp_owd20ms_n5/raw/summary.json`
  - `run_logs/test_cmp_paper/cmp_owd20ms_n10/raw/summary.json`
  - `run_logs/test_cmp_paper/cmp_owd50ms_n16/raw/summary.json`
- Notes: this command runs the paper's comparison grid, namely Net-L / Net-H, `n=5,10,16`, with one comparison per condition.

### Table III: fixed-point multiplication

- Script: `scripts/compare_fixedpoint_mul_a2.sh`
- Minimal command:

```sh
./scripts/compare_fixedpoint_mul_a2.sh -o run_logs/test_fixedpoint_paper
```

- Output directory: `run_logs/test_fixedpoint_paper/`
- Key output files:
  - `run_logs/test_fixedpoint_paper/semi-honest/p*.json`
  - `run_logs/test_fixedpoint_paper/malicious/p*.json`
- Notes: the script defaults now match the paper's Asterisk 2.0 rows, namely `n=5` and 1,000 consecutive fixed-point multiplications. Per-party execution logs are written under `run_logs/test_fixedpoint_paper/*/logs/`.

### Section: probabilistic truncation

- Script: `scripts/run_truncation_paper_grid.sh`
- Minimal command:

```sh
sudo ./scripts/run_truncation_paper_grid.sh --out-dir run_logs/test_truncation_paper
```

- Output directory: `run_logs/test_truncation_paper/`
- Key output files:
  - `run_logs/test_truncation_paper/owd20ms_n5/compare_output.txt`
  - `run_logs/test_truncation_paper/owd20ms_n5/raw/owd20ms_n5/summary.json`
  - `run_logs/test_truncation_paper/owd50ms_n10/raw/owd50ms_n10/summary.json`
  - `run_logs/test_truncation_paper/owd50ms_n16/raw/owd50ms_n16/summary.json`
- Notes: this command runs the paper's truncation grid, namely Net-L / Net-H, `n=5,10,16`, batch size 1,000, and single-latency repeat 5.

### Table V: volume matching

- Script: `scripts/run_vm_paper_grid.sh` (paper grid) or `scripts/compare_vm_protocols.sh` (single condition)
- Minimal command:

```sh
sudo ./scripts/run_vm_paper_grid.sh --out-dir run_logs/test_vm_paper
```

- Output directory: `run_logs/test_vm_paper/`
- Key output files:
  - `run_logs/test_vm_paper/vm_owd20ms_n5/raw/summary.json`
  - `run_logs/test_vm_paper/vm_owd20ms_n10/raw/summary.json`
  - `run_logs/test_vm_paper/vm_owd50ms_n16/raw/summary.json`
- Notes: this command runs the paper's VM grid with `M=N=32`, unit order size, and `n=5,10,16`.

### Table VI: continuous double auction

- Script: `scripts/run_cda_paper_grid.sh` (paper grid) or `scripts/compare_cda_protocols.sh` (single condition)
- Minimal command:

```sh
sudo ./scripts/run_cda_paper_grid.sh --out-dir run_logs/test_cda_paper
```

- Output directory: `run_logs/test_cda_paper/`
- Key output files:
  - `run_logs/test_cda_paper/cda_owd20ms_n5/raw/summary.json`
  - `run_logs/test_cda_paper/cda_owd20ms_n10/raw/summary.json`
  - `run_logs/test_cda_paper/cda_owd50ms_n16/raw/summary.json`
- Notes: this command runs the paper's CDA grid with `M=N=50` and `n=5,10,16`.

## Repository scope

- Asterisk baseline: `src/asterisk/`, `benchmark/asterisk_offline.cpp`, `benchmark/asterisk_online.cpp`, `benchmark/asterisk_cmp_offline.cpp`, `benchmark/asterisk_cmp_online.cpp`, `benchmark/Darkpool_VM.cpp`, and `benchmark/Darkpool_CDA.cpp`.
- Asterisk 2.0: `src/Asterisk2.0/` and the `benchmark/asterisk2_*` programs.
- Semi-honest Asterisk 2.0 benchmarks: run `benchmark/asterisk2_*` binaries with `--security-model semi-honest`.
- Malicious Asterisk 2.0 benchmarks: run `benchmark/asterisk2_*` binaries with `--security-model malicious`.
- The baseline Asterisk code is kept only for paper comparisons; the new protocol claims in the paper correspond to `src/Asterisk2.0/` and the `asterisk2_*` benchmark programs.
