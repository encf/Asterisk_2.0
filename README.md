# Asterisk

This directory contains the implementation of the Asterisk fair protocol.
The protocol is implemented in C++17 and [CMake](https://cmake.org/) is used as the build system.

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
  build-essential cmake git pkg-config \
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

If GitHub cloning is restricted in your environment, you can use the official
EMP installer script:

```sh
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python install.py --deps --tool
```

Then compile:

```sh
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
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

## Usage
A short description of the compiled programs is given below.
All of them provide detailed usage description on using the `--help` option.

- `benchmarks/asterisk_mpc`: Benchmark the performance of the Asterisk protocol (both offline and online phases) by evaluating a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/asterisk2_mpc`: Benchmark the performance of the Asterisk2.0 semi-honest Beaver multiplication protocol with one helper party and n computing parties.
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
# 安全模型参数（目前支持 semi-honest；malicious 预留接口）
./benchmarks/asterisk2_mpc -p $PID --localhost -g 100 -d 10 -n 5 --security-model semi-honest

# The `asterisk_mpc` script in the repository root can be used to run the programs 
# for all parties from the same terminal.
# For example, the previous benchmark can be run using the script as shown
# below.
./../asterisk_mpc.sh 100 10

# All other benchmark programs have similar options and behaviour. The '-h'
# option can be used for detailed usage information.

# Benchmark online phase for Asterisk MPC.
./../asterisk_online.sh 100 10

# Benchmark offline phase for Asterisk MPC.
./../asterisk_offline.sh 100 10

# Benchmark offline phase for Assisted MPC.
./../assistedmpc_offline.sh 100 10

# Benchmark Darkpool CDA algorithm for buy list size b=10 and sell list size s=20.
./../Darkpool_CDA.sh 10 20

# Benchmark Darkpool VM algorithm for buy list size = sell list size = 5/10/25/50/100.
./../Darkpool_VM.sh
```

## Asterisk2.0 vs Asterisk: 100 sequential multiplications

Use `g=1, d=100` to represent 100 sequential multiplications:

```sh
# Asterisk2.0 (semi-honest)
for pid in 0 1 2 3; do
  ./benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 -o asterisk2_chain100_p"$pid".json &
done
wait

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
- `offline_comm_count`, `online_comm_count`

当前实现已在在线阶段做按层 batched-open（把该层所有乘法门的 `d/e`
打包后一次发送/接收）以降低 RTT 开销。

本仓库内一次实际跑数结果可见：`docs_asterisk2_benchmark.md`。
