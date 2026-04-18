# Asterisk 2.0：论文 “Asterisk 2.0: Low-Latency MPC with a Friend via Optimistic Execution” 的代码材料

这个仓库实现了论文中的 semi-honest / malicious MPF 协议，包括 comparison、equality testing、probabilistic truncation 和 dark-pool benchmark。

为保证本机 loopback 复现不失真，建议把计算方数量 \(n\) 设为不超过机器可用的处理器线程数。否则，本地调度争用会主导测得延迟，从而扭曲论文中的实验结果。

下面列出的每个顶层复现脚本现在都使用统一的 localhost 启动器：主脚本会先为整组实验分配互不重叠的端口区间，再把端口通过命令行参数传给所有子进程，等待每个子进程回报网络初始化成功（`BOUND_OK`）或正常完成，并在失败时统一 kill/cleanup 其余子进程。同一台机器上建议一次只运行一个顶层复现脚本。

## 与论文的对应关系

- `src/Asterisk2.0/`：Asterisk 2.0 的核心协议实现。
- `benchmark/asterisk2_mpc.cpp`：乘法与截断 benchmark 入口。
- `benchmark/asterisk2_bgtez.cpp`：比较协议 benchmark 入口。
- `benchmark/asterisk2_eqz.cpp`：等式测试 benchmark 入口。
- `benchmark/asterisk2_darkpool_vm.cpp` 和 `benchmark/asterisk2_darkpool_cda.cpp`：dark-pool 应用 benchmark 入口。
- `scripts/run_*_paper_grid.sh`：按论文实验网格批量复现实验的脚本。

## 快速开始

1. 安装依赖。

```sh
./scripts/install_deps_ubuntu.sh
```

2. 编译 benchmark。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)" --target benchmarks
```

另外，这些复现脚本在启动前也会自动做增量编译，所以正常使用时不需要每次手动重新 build。

3. 跑一个 sanity check。

```sh
./build/benchmarks/asterisk2_mpc --help
```

## 论文结果复现映射

### 表 II：整数乘法

- 脚本：`scripts/run_table3_tc.sh`（论文网格）或 `scripts/compare_mul_protocols.sh`（单一条件）
- 最短命令：

```sh
sudo bash ./scripts/run_table3_tc.sh --out-dir run_logs/test_mul_paper
```

- 输出目录：`run_logs/test_mul_paper/`
- 关键输出文件：
  - `run_logs/test_mul_paper/table3_summary.csv`
  - `run_logs/test_mul_paper/table3_summary.md`
  - `run_logs/test_mul_paper/bw_100mbit_owd_20ms/n5/compare_output.txt`
  - `run_logs/test_mul_paper/bw_100mbit_owd_50ms/n16/compare_output.txt`
- 说明：该命令直接运行论文里的整数乘法实验网格，即 Net-L / Net-H、`n=5,10,16`、10,000 次连续依赖乘法。每个参与方的执行日志会写到对应运行目录下的 `logs/` 子目录中。
- 运行机制：`run_table3_tc.sh` 就是这一组实验的父启动脚本。它会先配置 `tc`，再为每个条件预留完整端口区间，统一拉起所有参与方，等待 ready 信号，并在失败时自动清理子进程。

### 表 IV：比较协议

- 脚本：`scripts/run_comparison_paper_grid.sh`（论文网格）或 `scripts/compare_cmp_protocols.sh`（单一条件）
- 最短命令：

```sh
sudo ./scripts/run_comparison_paper_grid.sh --out-dir run_logs/test_cmp_paper
```

- 输出目录：`run_logs/test_cmp_paper/`
- 关键输出文件：
  - `run_logs/test_cmp_paper/cmp_owd20ms_n5/raw/summary.json`
  - `run_logs/test_cmp_paper/cmp_owd20ms_n10/raw/summary.json`
  - `run_logs/test_cmp_paper/cmp_owd50ms_n16/raw/summary.json`
- 说明：该命令运行论文里的 comparison 实验网格，即 Net-L / Net-H、`n=5,10,16`，每个条件做单次比较。
- 运行机制：脚本会先为该条件一次性分配完整端口块，再按固定偏移切给 baseline / semi-honest / malicious 三组子实验。正常情况下不需要手动指定 `--base-port`。

### 表 III：定点数乘法

- 脚本：`scripts/compare_fixedpoint_mul_a2.sh`
- 最短命令：

```sh
./scripts/compare_fixedpoint_mul_a2.sh -o run_logs/test_fixedpoint_paper
```

- 输出目录：`run_logs/test_fixedpoint_paper/`
- 关键输出文件：
  - `run_logs/test_fixedpoint_paper/semi-honest/p*.json`
  - `run_logs/test_fixedpoint_paper/malicious/p*.json`
- 说明：该脚本默认参数现在已经和论文中的 Asterisk 2.0 行一致，即 `n=5`、1,000 次连续定点数乘法。每个参与方的执行日志会写到 `run_logs/test_fixedpoint_paper/*/logs/` 下。
- 运行机制：脚本会先一次性预留完整端口区间，然后分别分配给 semi-honest 和 malicious 两段运行。

### 小节：概率截断

- 脚本：`scripts/run_truncation_paper_grid.sh`
- 最短命令：

```sh
sudo ./scripts/run_truncation_paper_grid.sh --out-dir run_logs/test_truncation_paper
```

- 输出目录：`run_logs/test_truncation_paper/`
- 关键输出文件：
  - `run_logs/test_truncation_paper/owd20ms_n5/compare_output.txt`
  - `run_logs/test_truncation_paper/owd20ms_n5/raw/owd20ms_n5/summary.json`
  - `run_logs/test_truncation_paper/owd50ms_n10/raw/owd50ms_n10/summary.json`
  - `run_logs/test_truncation_paper/owd50ms_n16/raw/owd50ms_n16/summary.json`
- 说明：该命令运行论文中的 truncation 网格，即 Net-L / Net-H、`n=5,10,16`、batch size 1,000，并保留 single-latency repeat 5 的论文设定。
- 运行机制：每个条件都作为一组受父脚本控制的子进程启动。父脚本会在真正启动前预留 `single/batch × semi-honest/malicious` 所需的完整端口范围。

### 表 V：Volume Matching

- 脚本：`scripts/run_vm_paper_grid.sh`（论文网格）或 `scripts/compare_vm_protocols.sh`（单一条件）
- 最短命令：

```sh
sudo ./scripts/run_vm_paper_grid.sh --out-dir run_logs/test_vm_paper
```

- 输出目录：`run_logs/test_vm_paper/`
- 关键输出文件：
  - `run_logs/test_vm_paper/vm_owd20ms_n5/raw/summary.json`
  - `run_logs/test_vm_paper/vm_owd20ms_n10/raw/summary.json`
  - `run_logs/test_vm_paper/vm_owd50ms_n16/raw/summary.json`
- 说明：该命令运行论文中的 VM 网格，参数为 `M=N=32`、unit order size、`n=5,10,16`。
- 运行机制：VM 对比脚本会先预留一整块端口，再划分给 legacy baseline、semi-honest 和 malicious 三段运行。

### 表 VI：Continuous Double Auction

- 脚本：`scripts/run_cda_paper_grid.sh`（论文网格）或 `scripts/compare_cda_protocols.sh`（单一条件）
- 最短命令：

```sh
sudo ./scripts/run_cda_paper_grid.sh --out-dir run_logs/test_cda_paper
```

- 输出目录：`run_logs/test_cda_paper/`
- 关键输出文件：
  - `run_logs/test_cda_paper/cda_owd20ms_n5/raw/summary.json`
  - `run_logs/test_cda_paper/cda_owd20ms_n10/raw/summary.json`
  - `run_logs/test_cda_paper/cda_owd50ms_n16/raw/summary.json`
- 说明：该命令运行论文中的 CDA 网格，参数为 `M=N=50`、`n=5,10,16`。
- 运行机制：CDA 对比脚本采用和 VM、comparison 相同的父脚本统一启动方式。

## 仓库范围说明

- Asterisk 基线：`src/asterisk/`、`benchmark/asterisk_offline.cpp`、`benchmark/asterisk_online.cpp`、`benchmark/asterisk_cmp_offline.cpp`、`benchmark/asterisk_cmp_online.cpp`、`benchmark/Darkpool_VM.cpp`、`benchmark/Darkpool_CDA.cpp`。
- Asterisk 2.0：`src/Asterisk2.0/` 以及所有 `benchmark/asterisk2_*` 程序。
- Asterisk 2.0 的 semi-honest benchmark：运行 `benchmark/asterisk2_*` 时使用 `--security-model semi-honest`。
- Asterisk 2.0 的 malicious benchmark：运行 `benchmark/asterisk2_*` 时使用 `--security-model malicious`。
- 旧版 Asterisk 代码仅用于论文中的 baseline 对比；论文中新的协议实现和主要结论对应的是 `src/Asterisk2.0/` 和 `asterisk2_*` benchmark。
