# Asterisk

This directory contains the implementation of the Asterisk fair protocol.
The protocol is implemented in C++17 and [CMake](https://cmake.org/) is used as the build system.

Field modulus is unified to:

```text
p = 2^64 - 59 = 18446744073709551557
```

## 🧭 开发执行清单（贡献者工作流）

为保证每次任务可复现、可交接，建议在开发时固定执行以下流程：

1. **先检查依赖再开发**：确认 `cmake`、`g++`、`openssl`、`gmp`、`ntl`、`boost`、`nlohmann-json`、`emp-tool` 可用；缺失则先安装。
2. **阶段化更新进度**：每完成一个阶段（如“分析 / 开发 / 验证”），同步更新任务进度记录（例如 `TASK_HANDOFF.md`）。
3. **改完必须验证**：至少运行可执行的构建或测试命令（例如 `cmake --build ...` / `ctest`）。
4. **同步文档**：代码行为、脚本参数、实验方式有变化时，必须同步更新 README / docs / handoff 文档，保证后续同学可直接接手。

## 🚀 从零开始跑通（Ubuntu 小白版）

> 下面按“复制即可执行”的顺序写好，默认你在 Ubuntu 22.04/24.04。

### 0) 获取代码
```sh
git clone <你的仓库地址> Asterisk
cd Asterisk
```

### 1) 安装系统依赖
```sh
sudo apt-get update
sudo apt-get install -y \
  build-essential ccache cmake git pkg-config \
  libgmp-dev libntl-dev libboost-all-dev nlohmann-json3-dev libssl-dev
```

### 2) 安装 EMP Tool（推荐先用官方脚本）
```sh
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python install.py --deps --tool
```

如果你所在网络环境里 `git clone github.com` 不稳定/被限制，可用 tarball 方式安装：
```sh
wget -O /tmp/emp-tool.tar.gz https://codeload.github.com/emp-toolkit/emp-tool/tar.gz/refs/heads/master
tar -xzf /tmp/emp-tool.tar.gz -C /tmp
cmake -S /tmp/emp-tool-master -B /tmp/emp-tool-master/build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/emp-tool-master/build -j"$(nproc)"
sudo cmake --install /tmp/emp-tool-master/build
```

### 3) 编译项目
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)" --target benchmarks tests

# 推荐：启用 ccache 以加速重复编译
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
cmake --build build -j"$(nproc)" --target benchmarks tests
```

### 4) 先做一个最小验收（确认真的跑通）
```sh
./build/benchmarks/asterisk_mpc --help
./build/benchmarks/asterisk2_mpc --help
```

### 5) 跑一个最小实验（4 个本地进程：3 个计算方 + 1 个 helper）
```sh
for pid in 0 1 2 3; do
  ./build/benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 10 -r 1 \
    --security-model semi-honest -o /tmp/a2_quickstart_p"$pid".json &
done
wait
```

### 6) 常见报错速查
- **`Could not find ... emp-toolConfig.cmake`**：EMP Tool 没安装成功，回到第 2 步重新安装。
- **`Address already in use`**：端口冲突；换 `--port` 或等上次进程退出。
- **多进程卡住**：通常是某个 `pid` 没启动齐（`0..n` 必须全起）。

### 7) 三种乘法协议一键对比（offline/online 通信与耗时）
新增脚本：`scripts/compare_mul_protocols.sh`，会自动跑并汇总：
- Asterisk（`asterisk_offline` + `asterisk_online`）
- Asterisk2.0 semi-honest（`asterisk2_mpc --security-model semi-honest`）
- Asterisk2.0 malicious（`asterisk2_mpc --security-model malicious`）

输出指标（平均值）：
- offline communication（MB）
- offline time（s）
- online communication（MB）
- online time（s）

```sh
# 示例：n=3 个计算方，连续乘法次数=10（depth=10，默认每层 1 个乘法门）
./scripts/compare_mul_protocols.sh -n 3 -d 10 -r 3

# 可调参数
./scripts/compare_mul_protocols.sh --help
```

> 说明：脚本会启动 `pid=0..n`（含 helper），并把每个 party 的原始 JSON 保存到
> `run_logs/protocol_compare/` 下。

### 8) 网络环境设置（延迟/带宽）

#### 方式 A：真实网络整形（推荐，用于端到端实验）
在 Linux 上可用 `tc netem + tbf` 对网卡施加延迟和带宽限制。

依赖（Ubuntu）：
```sh
sudo apt-get update
sudo apt-get install -y iproute2
```

示例（把 `eth0` 改成你的网卡名）：
```sh
# 添加：固定 20ms 延迟，带宽限制 100mbit
sudo tc qdisc replace dev eth0 root handle 1: netem delay 20ms
sudo tc qdisc replace dev eth0 parent 1: handle 10: tbf rate 100mbit burst 64kb latency 50ms

# 查看
tc qdisc show dev eth0

# 清除
sudo tc qdisc del dev eth0 root
```

如果你要**一键恢复默认网络状态**（避免遗留限速/延迟），可执行：
```sh
# 删除 root qdisc（若不存在则忽略报错）
sudo tc qdisc del dev eth0 root 2>/dev/null || true

# 确认已经恢复（通常显示 fq_codel/pfifo_fast 等默认队列）
tc qdisc show dev eth0
```

#### 方式 B：通信代价模型（快速估算，不改变真实链路）
`benchmarks/asterisk2_mpc` 支持内置模型参数：
- `--net-preset lan|wan`
- 或 `--bandwidth-bps` + `--latency-ms`

例如：
```sh
./build/benchmarks/asterisk2_mpc --localhost -n 3 -p 0 -g 1 -d 10 -r 1 \
  --security-model semi-honest --bandwidth-bps 100000000 --latency-ms 20
```

### 9) 比较协议对比脚本（Asterisk / Asterisk2.0 SH / Asterisk2.0 malicious）
新增脚本：`scripts/compare_cmp_protocols.sh`，输出三方对比表：
- offline communication（MB）
- offline time（s）
- online communication（MB）
- online time（s）

```sh
# 示例：n=3 个计算方，比较次数=20
./scripts/compare_cmp_protocols.sh -n 3 -c 20

# 可调参数（含 lx/slack）
./scripts/compare_cmp_protocols.sh --help
```

参数说明：
- `-n/--num-parties`：计算方数量
- `-c/--compare-count`：比较次数（Asterisk2.0 BGTEZ 使用 repeat 跑多次比较）

> 备注：当前仓库里 Asterisk（旧协议）没有独立 BGTEZ benchmark 二进制，
> 脚本中的 `Asterisk (baseline)` 使用现有 `asterisk_offline` + `asterisk_online`
> 作为基线口径进行 offline/online 通信与时间对比。

### 10) 定点数乘法（一次整数乘法 + 一次截断）对比脚本
新增脚本：`scripts/compare_fixedpoint_mul_a2.sh`，对比：
- Asterisk2.0 semi-honest
- Asterisk2.0 malicious

输出指标（单位已统一）：
- offline communication（MB）
- offline time（s）
- online communication（MB）
- online time（s）

```sh
# 示例：n=3 个计算方，定点数乘法次数=20
./scripts/compare_fixedpoint_mul_a2.sh -n 3 -c 20

# 可调参数
./scripts/compare_fixedpoint_mul_a2.sh --help
```

参数说明：
- `-n/--num-parties`：计算方数量
- `-c/--fixed-mul-count`：定点数乘法次数
- `--frac-bits`：截断的小数位数 m
- `--ell-x`、`--slack`：截断参数

## External Dependencies
The following libraries need to be installed separately and should be available to the build system and compiler.

- [GMP](https://gmplib.org/)
- [NTL](https://www.shoup.net/ntl/) (11.0.0 or later)
- [Boost](https://www.boost.org/) (1.72.0 or later)
- [Nlohmann JSON](https://github.com/nlohmann/json)
- [EMP Tool](https://github.com/emp-toolkit/emp-tool)

### Docker
All required dependencies to compile and run the project are available through the docker image.
To build and run the docker image, execute the following commands from the root directory of the repository:

```sh
# Build the Asterisk Docker image.
#
# Building the Docker image requires at least 4GB RAM. This needs to be set 
# explicitly in case of Windows and MacOS.
docker build -t asterisk .

# Create and run a container.
#
# This should start the shell from within the container.
docker run -it -v $PWD:/code asterisk

# The following command changes the working directory to the one containing the 
# source code and should be run on the shell started using the previous command.
cd /code
```

## Compilation
The project uses [CMake](https://cmake.org/) for building the source code. 
To compile, run the following commands from the root directory of the repository:

```sh
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..

# The two main targets are 'benchmarks' and 'tests' corresponding to
# binaries used to run benchmarks and unit tests respectively.
make <target>
```

### Ubuntu one-click dependency install
On Ubuntu, you can install all required dependencies (including `emp-tool`) with:

```sh
./scripts/install_deps_ubuntu.sh
```

该脚本会安装 `ccache`，并在构建 `emp-tool` 时启用 compiler launcher。

If GitHub cloning is restricted in your environment, you can use the official
EMP installer script:

```sh
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python install.py --deps --tool
```

Then compile:

```sh
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache ..
make -j"$(nproc)" tests benchmarks
```

### Example: 10 sequential multiplications (MPC)
This repo can express "10 sequential multiplications" as a circuit with:
- depth = `10`
- multiplication gates per depth = `1`

After building benchmarks, run:

```sh
./mpc_10_chain_mul.sh 3
```

This starts party IDs `0..3` locally and stores logs under:
`./run_logs/chain_mul_10/`.

## Asterisk2.0 malicious roadmap

- 详细的恶意安全实现任务分解见：`docs/asterisk2_malicious_implementation_plan.md`。
- 该路线图把实现拆分为认证分享、延迟验证、公平输出释放、恶意乘法、trunc/compare 升级、benchmark 与测试。
- 当前已落地：malicious 乘法离线/在线分派、authenticated tuple 预处理、`Pi_MACSetup-DH` 与显式 `KeyManager`（`[Δ]` / `[Δ^{-1}]` 由 `runMacSetupDH` 提供）。
- `KeyManager` 当前维护两类会话密钥：helper<->party pairwise key，以及仅计算方共享的 `K_P`（用于 `compare_offline` 共享掩码/置换生成）。
- malicious 输入分享已接入：按 `x' = x + r + t` 与 helper 补足 share 的流程生成 `[x]`/`[Δx]`（当前输入 owner 约定为 `P0`）；一致性检查改由单元测试覆盖。
- malicious 乘法离线预处理已接入 authenticated tuple：除 `[a],[b],[ab]` 外，还会生成 `[a'],[b'],[c'],[a'b'],[a'c'],[b'c'],[a'b'c']` 的 additive shares。
- `Pi_MACSetup-DH` 现在在 malicious 模式协议初始化阶段执行一次；后续 `mul_offline_malicious` 仅复用已缓存的 `[Δ]/[Δ^{-1}]` 份额。
- `mul_online_malicious` 当前按门级在线流程打开 `d,e,d_Δ,e_Δ,f`，并在本地同步组装 `[xy]` 与 `[Δxy]`（已移除旧的 helper 端输出重构一致性检查路径）。
- 已新增 malicious 认证概率截断 split 接口：`trunc_offline_malicious(...)` 与 `trunc_online_malicious(...)`，可从 `[x],[Δx]` 输出 `[Trunc_m(x)],[ΔTrunc_m(x)]`。
- 已新增 malicious 认证比较 split 接口：`compare_offline_malicious(...)` 与 `compare_online_malicious(...)`，输入 `[x],[Δx]` 输出 `[GTEZ(x)],[ΔGTEZ(x)]`，在线流程固定为 3 轮。
- 当前仍在开发：Ver-DH、deferred batch verify、fair release。

## Usage
A short description of the compiled programs is given below.
All of them provide detailed usage description on using the `--help` option.

- `benchmarks/asterisk_mpc`: Benchmark the performance of the Asterisk protocol (both offline and online phases) by evaluating a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/asterisk2_mpc`: Benchmark the performance of the Asterisk2.0 semi-honest Beaver multiplication protocol with one helper party and n computing parties.
- `benchmarks/asterisk2_bgtez`: Benchmark the Asterisk2.0 BGTEZ-SH batched comparison protocol and output online/offline/communication metrics.
- `benchmarks/asterisk_online`: Benchmark the performance of the Asterisk online phase for a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/asterisk_offline`: Benchmark the performance of the Asterisk offline phase for a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/assistedmpc_offline`: Benchmark the performance of the Assisted MPC offline phase for a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/Darkpool_CDA`: Benchmark the performance of the Darkpool CDA algorithm for a given buy list and sell list size.
- `benchmarks/Darkpool_VM`: Benchmark the performance of the Darkpool VM algorithm for a given buy list and sell list size. Here, the number of parties = buy list size + sell list size.
- `tests/*`: These programs contain unit tests for various parts of the codebase. 

Execute the following commands from the `build` directory created during compilation to run the programs:
```sh
# Benchmark Asterisk MPC.
#
# The command below should be run on n+1 different terminals with $PID set to
# 0, 1, 2, upto n i.e., one instance corresponding to each party.
#
# The number of threads can be set using the '-t' option. '-g' denotes the 
# number of gates at each level, '-d' denotes the depth of the circuit and '-n'
# the number of parties participating in the protocol.
#
# The program can be run on different machines by replacing the `--localhost`
# option with '--net-config <net_config.json>' where 'net_config.json' is a
# JSON file containing the IPs of the parties. A template is given in the
# repository root.
./benchmarks/asterisk_mpc -p $PID --localhost -g 100 -d 10 -n 5

# Benchmark Asterisk2.0 semi-honest Beaver MPC.
#
# 该程序需要启动 n+1 个进程：其中 0..n-1 为计算方，n 为 helper。
./benchmarks/asterisk2_mpc -p $PID --localhost -g 100 -d 10 -n 5
# 安全模型参数（semi-honest 完整可用；malicious 为开发中实验路径）
./benchmarks/asterisk2_mpc -p $PID --localhost -g 100 -d 10 -n 5 --security-model semi-honest
# 说明：benchmark 内部会按安全模型走对应的 mul_offline/mul_online 路径，
# 以保留 malicious 所需的离线材料（不仅是 triples）。
# 在 malicious 模式下，helper 也会参与 online 流程（例如输入分享阶段）。
# 可选：开启在线阶段并行对端发送/接收，并按并行链路口径统计发送次数
./benchmarks/asterisk2_mpc -p $PID --localhost -g 100 -d 10 -n 5 --parallel-send
# 可选：通信代价模型预设（LAN/WAN）
./benchmarks/asterisk2_mpc -p $PID --localhost -g 100 -d 10 -n 5 --net-preset lan
# 可选：自定义通信代价模型参数（单位：bps / ms）
./benchmarks/asterisk2_mpc -p $PID --localhost -g 100 -d 10 -n 5 \
  --bandwidth-bps 100000000 --latency-ms 20

# semi-honest 模式会输出在线阶段细分字段：
# - online_network_overhead_ms（当前实现重点统计）
# - online_local_compute_ms（预留字段，当前不再单独计时）

# The `asterisk_mpc` script in the repository root can be used to run the programs 
# for all parties from the same terminal.
# For example, the previous benchmark can be run using the script as shown
# below.
./../asterisk_mpc.sh 100 10

# All other benchmark programs have similar options and behaviour. The '-h'
# option can be used for detailed usage information.

# Benchmark online phase for Asterisk MPC.
./../asterisk_online.sh 100 10
# 可选：为 Asterisk online 统计增加网络仿真时间估计
./benchmarks/asterisk_online --localhost -n 3 -p $PID -g 1 -d 100 -r 1 \
  --sim-latency-ms 2 --sim-bandwidth-mbps 50 --sim-rounds-per-depth 2
# 可选：通信代价模型预设（会输出每轮与总通信时间估计）
./benchmarks/asterisk_online --localhost -n 3 -p $PID -g 1 -d 100 -r 1 --net-preset wan

# Benchmark offline phase for Asterisk MPC.
./../asterisk_offline.sh 100 10

# Benchmark offline phase for Assisted MPC.
./../assistedmpc_offline.sh 100 10

# Benchmark Darkpool CDA algorithm for buy list size b=10 and sell list size s=20.
./../Darkpool_CDA.sh 10 20

# Benchmark Darkpool VM algorithm for buy list size = sell list size = 5/10/25/50/100.
./../Darkpool_VM.sh
```

### Asterisk2.0 protocol API (offline/online split)

`src/Asterisk2.0/protocol.h` now exposes explicit offline/online pairs for the three protocol families:

- multiplication: `mul_offline(...)` + `mul_online(...)`
- truncation: `trunc_offline(...)` + `trunc_online(...)`
- comparison (BGTEZ): `compare_offline(...)` + `compare_online(...)`

Legacy wrappers (`offline/online`, `probabilisticTruncate`, `bgtezCompare`) are kept for compatibility and internally call the split APIs.

## Asterisk2.0 vs Asterisk: 100 sequential multiplications

Use `g=1, d=100` to represent 100 sequential multiplications:

```sh
# Asterisk2.0 (semi-honest)
for pid in 0 1 2 3; do
  ./benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 -o asterisk2_chain100_p"$pid".json &
done
wait

# 可选：导出每个计算方的本地输出 share（用于正确性校验）
for pid in 0 1 2 3; do
  ./benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 10 -r 1 \
    --security-model semi-honest --dump-output-shares \
    -o /tmp/a2_mul_check_p"$pid".json &
done
wait
# 一键重建输出并校验（期望值按 5^(2^d) mod p 计算）
python3 scripts/verify_asterisk2_mul.py --depth 10 --out-dir /tmp/a2_mul_verify

# 可选：对在线输出继续执行 Asterisk2.0 算术域概率截断（Trunc-SH）
# 例：移除 m=8 个小数位，ell_x=40，统计裕量 s=8
for pid in 0 1 2 3; do
  ./benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 10 -r 1 \
    --security-model semi-honest --dump-output-shares \
    --trunc-frac-bits 8 --trunc-lx 40 --trunc-slack 8 \
    -o /tmp/a2_trunc_check_p"$pid".json &
done
wait

# 说明：乘法 online 与 truncation 统计已分开输出
# - online.* / online_bytes: 仅乘法在线阶段
# - truncation_offline.* / truncation_offline_bytes: 仅截断离线阶段
# - truncation.* / truncation_bytes: 仅截断在线阶段

# BGTEZ-SH（批量截断+比较）单测已加入：
# - tests/asterisk2_bgtez_test

# Asterisk baseline: offline + online split
for pid in 0 1 2 3; do
  ./benchmarks/asterisk_offline --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 -o asterisk_offline_chain100_p"$pid".json &
done
wait

for pid in 0 1 2 3; do
  ./benchmarks/asterisk_online --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 -o asterisk_online_chain100_p"$pid".json &
done
wait
```

`asterisk2_mpc` 输出中包含以下关键字段便于对比：
- `offline.time`, `online.time`
- `offline_bytes`, `online_bytes`
- `offline_comm_count`
- `online_comm_rounds`（在线交互轮次，当前按乘法门数量统计）
- `online_send_count`（在线 send 次数，`online_comm_rounds * (n-1)`）
- 若开启 `--parallel-send`，在线开值阶段将并行对端发送/接收，
  且 `online_send_count` 统计为每轮 1 次逻辑发送。
  对很窄的层（例如 `g=1`）会自动退化为串行路径以避免线程开销。
- 若开启通信代价模型（`--net-preset` 或 `--bandwidth-bps/--latency-ms`）：
  - `comm_model_round_ms`：每轮通信时间估计
  - `comm_model_total_ms`：总通信时间估计
- `online_comm_count`（兼容旧字段，当前等于 `online_comm_rounds`）

当前实现中，semi-honest 乘法在线路径采用“按门 open（每门一次）”策略，
恶意路径同样使用按门开值（每门会打开 `d,e,d_Δ,e_Δ,f`）。

本仓库内一次实际跑数结果可见：`docs_asterisk2_benchmark.md`。

### Communication cost model (for experiments)

支持一个简化通信模型（传播时延 + 发送时延，忽略排队和协议开销）：

- 单轮：`round_time = latency_ms + (bytes_sent * 8) * 1000 / bandwidth_bps`
- all-to-all（每方向其余 `n-1` 方各发 `msg_size_bytes`，且总出口带宽共享）：
  `round_time = latency_ms + (msg_size_bytes * (n-1) * 8) * 1000 / bandwidth_bps`

预设：
- `LAN`: `bandwidth_bps=1_000_000_000`, `latency_ms=1`
- `WAN`: `bandwidth_bps=100_000_000`, `latency_ms=20`

可复用脚本：
```sh
python3 scripts/network_cost_model.py --preset lan --bytes-sent 4096 --rounds 100
python3 scripts/network_cost_model.py --preset wan --msg-size-bytes 16 --parties 5 --rounds 100
```
