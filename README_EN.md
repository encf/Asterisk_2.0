# Asterisk 2.0: Artifact for “Asterisk 2.0: Low-Latency MPC with a Friend via Optimistic Execution”

This repository implements the paper's semi-honest and malicious MPF protocols, including comparison, equality testing, probabilistic truncation, and dark-pool benchmarks.

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

### Table II in the paper: integer multiplication

- Script: `scripts/compare_mul_protocols.sh`
- Minimal command:

```sh
./scripts/compare_mul_protocols.sh -n 3 -d 10 -r 3 -o run_logs/reviewer_mul
```

- Output directory: `run_logs/reviewer_mul/`
- Key output files:
  - `run_logs/reviewer_mul/asterisk_offline/p*.json`
  - `run_logs/reviewer_mul/asterisk_online/p*.json`
  - `run_logs/reviewer_mul/asterisk2_semi_honest/p*.json`
  - `run_logs/reviewer_mul/asterisk2_malicious/p*.json`
- Notes: the script prints the final comparison table to stdout and saves raw per-party JSON files under the output directory.

### Table IV in the paper: comparison

- Script: `scripts/compare_cmp_protocols.sh`
- Minimal command:

```sh
./scripts/compare_cmp_protocols.sh -n 3 -c 20 --label reviewer_cmp
```

- Output directory: `run_logs/compare_protocols/reviewer_cmp/`
- Key output files:
  - `run_logs/compare_protocols/reviewer_cmp/summary.json`
  - `run_logs/compare_protocols/reviewer_cmp/asterisk_offline/p*.json`
  - `run_logs/compare_protocols/reviewer_cmp/asterisk_online/p*.json`
  - `run_logs/compare_protocols/reviewer_cmp/asterisk2_bgtez_sh/p*.json`
  - `run_logs/compare_protocols/reviewer_cmp/asterisk2_bgtez_mal/p*.json`

### Table III in the paper: fixed-point multiplication

- Script: `scripts/compare_fixedpoint_mul_a2.sh`
- Minimal command:

```sh
./scripts/compare_fixedpoint_mul_a2.sh -n 3 -c 20 -o run_logs/reviewer_fixedpoint
```

- Output directory: `run_logs/reviewer_fixedpoint/`
- Key output files:
  - `run_logs/reviewer_fixedpoint/semi-honest/p*.json`
  - `run_logs/reviewer_fixedpoint/malicious/p*.json`
- Notes: the script prints the summary table to stdout; the raw benchmark records are stored in the per-model JSON files above.

### Section in the paper: probabilistic truncation

- Script: `scripts/run_truncation_tc_matrix.sh`
- Minimal command:

```sh
./scripts/run_truncation_tc_matrix.sh --out-dir run_logs/reviewer_truncation_matrix
```

- Output directory: `run_logs/reviewer_truncation_matrix/`
- Key output files:
  - `run_logs/reviewer_truncation_matrix/owd20ms_n5/compare_output.txt`
  - `run_logs/reviewer_truncation_matrix/owd20ms_n5/raw/owd20ms_n5/summary.json`
  - `run_logs/reviewer_truncation_matrix/owd50ms_n10/raw/owd50ms_n10/summary.json`
  - `run_logs/reviewer_truncation_matrix/owd50ms_n16/raw/owd50ms_n16/summary.json`
- Notes: this script configures `tc` on loopback and therefore requires `sudo` in an interactive terminal.

### Table V in the paper: volume matching

- Script: `scripts/compare_vm_protocols.sh`
- Minimal command:

```sh
./scripts/compare_vm_protocols.sh --label reviewer_vm
```

- Output directory: `run_logs/vm_protocols/reviewer_vm/`
- Key output files:
  - `run_logs/vm_protocols/reviewer_vm/summary.json`
  - `run_logs/vm_protocols/reviewer_vm/summary.md`
  - `run_logs/vm_protocols/reviewer_vm/asterisk_vm/p*.json`
  - `run_logs/vm_protocols/reviewer_vm/asterisk2_vm_sh/p*.json`
  - `run_logs/vm_protocols/reviewer_vm/asterisk2_vm_dh/p*.json`

### Table VI in the paper: continuous double auction

- Script: `scripts/compare_cda_protocols.sh`
- Minimal command:

```sh
./scripts/compare_cda_protocols.sh --label reviewer_cda
```

- Output directory: `run_logs/cda_protocols/reviewer_cda/`
- Key output files:
  - `run_logs/cda_protocols/reviewer_cda/summary.json`
  - `run_logs/cda_protocols/reviewer_cda/summary.md`
  - `run_logs/cda_protocols/reviewer_cda/asterisk_cda/p*.json`
  - `run_logs/cda_protocols/reviewer_cda/asterisk2_cda_sh/p*.json`
  - `run_logs/cda_protocols/reviewer_cda/asterisk2_cda_dh/p*.json`

## Repository scope

- Asterisk baseline: `src/asterisk/`, `benchmark/asterisk_offline.cpp`, `benchmark/asterisk_online.cpp`, `benchmark/asterisk_cmp_offline.cpp`, `benchmark/asterisk_cmp_online.cpp`, `benchmark/Darkpool_VM.cpp`, and `benchmark/Darkpool_CDA.cpp`.
- Asterisk 2.0: `src/Asterisk2.0/` and the `benchmark/asterisk2_*` programs.
- Semi-honest Asterisk 2.0 benchmarks: run `benchmark/asterisk2_*` binaries with `--security-model semi-honest`.
- Malicious Asterisk 2.0 benchmarks: run `benchmark/asterisk2_*` binaries with `--security-model malicious`.
- The baseline Asterisk code is kept only for paper comparisons; the new protocol claims in the paper correspond to `src/Asterisk2.0/` and the `asterisk2_*` benchmark programs.
