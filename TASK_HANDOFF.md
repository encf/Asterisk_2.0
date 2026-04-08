# TASK_HANDOFF

## 1) 任务目标
- [done] 为 MPC 实验提供可复用的“简化通信代价模型”，支持可配置 `bandwidth_bps`、`latency_ms`，并支持 LAN/WAN 预设。
- [done] 在 `asterisk2_mpc` 与 `asterisk_online` 中输出“每轮通信时间”和“总通信时间”估计，便于实验对比与自动化采集。
- [partial] 用文档与脚本把该模型沉淀为后续任务可直接复用的工程接口。

## 2) 当前进度（已完成 / 部分完成 / 未开始）
- [done] 新增 C++ 头文件 `src/utils/network_cost_model.h`，提供：
  - `presetNetworkCostModel()`（`lan`/`wan`/`none`）
  - `resolveNetworkCostModel()`（预设 + 显式参数覆盖）
  - `estimateRoundTimeMs()`（通用单轮）
  - `estimateAllToAllRoundTimeMs()`（all-to-all 共享出口带宽）
  - `estimateTotalTimeMs()`
- [done] `benchmark/asterisk2_mpc.cpp` 接入新参数：
  - `--net-preset`、`--bandwidth-bps`、`--latency-ms`
  - 输出字段：`comm_model_round_ms`、`comm_model_total_ms`
  - 控制台打印上述估计值
- [done] `benchmark/asterisk_online.cpp` 接入同样参数与输出字段。
- [done] 新增脚本 `scripts/network_cost_model.py`，用于实验脚本快速估算（generic / all-to-all）。
- [done] README 与基准文档更新：新增模型公式、预设说明、命令示例。
- [partial] 已做功能性 smoke 与实测跑数；尚缺“固定随机种子 + 稳定回归阈值”的 CI 化对比基线。
- [todo] 统一 Asterisk 与 Asterisk2.0 的“rounds 定义口径”说明，避免跨协议对比时被误读。

## 3) 改动文件清单（每个文件一句说明）
- `src/utils/network_cost_model.h`：通信代价模型核心实现（公式、预设、总时长估计）。
- `benchmark/asterisk2_mpc.cpp`：新增通信模型 CLI 参数，写入 JSON 与控制台输出估计值。
- `benchmark/asterisk_online.cpp`：新增通信模型 CLI 参数，写入 JSON 与控制台输出估计值。
- `scripts/network_cost_model.py`：独立可复用脚本，便于外部实验脚本直接调用。
- `README.md`：补充通信模型公式、LAN/WAN 预设、基准命令示例。
- `docs_asterisk2_benchmark.md`：补充通信模型开关与输出字段说明。

## 4) 关键设计决策与约束
- [done] 模型选择：
  - 采用**简化模型**：传播时延 + 发送时延。
  - 明确**忽略**排队延迟、重传、分片、协议开销。
- [done] 预设参数固定：
  - LAN = `1_000_000_000 bps`, `1 ms`
  - WAN = `100_000_000 bps`, `20 ms`
- [done] 参数覆盖策略：
  - 先应用 `--net-preset`，再用 `--bandwidth-bps/--latency-ms` 覆盖（若 >0）。
- [partial] 跨协议可比性约束：
  - Asterisk2.0 使用 batched-open 的 `online_comm_rounds`。
  - Asterisk online 目前使用 `depth * sim_rounds_per_depth` 作为估计轮次。
  - 两者“轮次语义”不同，数值可比前需先统一口径。
- [done] 无侵入协议逻辑：
  - 通信模型只做估算与输出，不改变协议正确性路径。

## 5) 剩余待办（按优先级排序）
- [todo][P0] 统一/显式化 round 口径：
  - 给 Asterisk online 增加更精确的“实际交互轮次统计”字段，减少依赖 `sim_rounds_per_depth` 近似。
- [todo][P1] 增加回归测试：
  - 为 `network_cost_model.h` 和 `scripts/network_cost_model.py` 添加最小单元测试（公式、预设、覆盖逻辑）。
- [todo][P1] 在 benchmark 输出中增加 `comm_model_assumption` 字段：
  - 标注 generic/all-to-all 估计模式，避免后处理脚本误读。
- [todo][P2] 增加一键对比脚本：
  - 固定参数跑 Asterisk vs Asterisk2.0 并产出汇总表（CSV/Markdown）。
- [todo][P2] 文档补充“如何解释 raw time 与 model time 差异”的 FAQ。

## 6) 风险与未验证点
- [partial] 风险：跨协议 round 口径不同，`comm_model_total_ms` 横向比较可能被放大/缩小。
- [partial] 风险：本地 `localhost` 跑数与真实 LAN/WAN 仍有系统调度噪声，模型值仅作估算基线。
- [todo] 未验证：更宽电路（如 `g>=64`）和更多参与方（`n>5`）下模型与实测偏差区间。
- [todo] 未验证：不同 CPU/内核网络栈对 raw time 的影响是否需要单独校准因子。

## 7) 验证方法（命令 + 通过标准）
- [done] 构建：
  - 命令：`cmake -S . -B build && cmake --build build -j4`
  - 通过标准：编译成功，`build/benchmarks/asterisk2_mpc` 和 `build/benchmarks/asterisk_online` 可执行。
- [done] 测试：
  - 命令：`ctest --test-dir build --output-on-failure -j1`
  - 通过标准：`100% tests passed`。
- [done] Asterisk2.0 模型字段 smoke：
  - 命令：
    `for pid in 0 1 2 3; do ./build/benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 5 -r 1 --security-model semi-honest --net-preset wan -o /tmp/model_a2_p"$pid".json & done; wait`
  - 通过标准：控制台出现 `comm_model_round_ms/comm_model_total_ms`；JSON 中存在同名字段且 >0（计算方）。
- [done] Asterisk online 模型字段 smoke：
  - 命令：
    `for pid in 0 1 2 3; do ./build/benchmarks/asterisk_online --localhost -n 3 -p "$pid" -g 1 -d 5 -r 1 --net-preset lan -o /tmp/model_ast_p"$pid".json & done; wait`
  - 通过标准：控制台出现 `comm_model_round_ms/comm_model_total_ms`；JSON 中存在同名字段。
- [done] 脚本复用验证：
  - 命令：`python3 scripts/network_cost_model.py --preset wan --msg-size-bytes 16 --parties 5 --rounds 100`
  - 通过标准：输出 `round_time_ms` 与 `total_time_ms`，数值 > 0。

## 8) 给下一任务的建议提示词
- [todo] `请统一 Asterisk 与 Asterisk2.0 的通信轮次统计口径，并在两个 benchmark JSON 中输出同名字段（例如 actual_online_rounds），同时补充回归测试与文档。`
- [todo] `请新增 scripts/compare_mpc_costs.py：自动运行 Asterisk/Asterisk2.0，汇总 raw time、bytes、comm_model_round_ms、comm_model_total_ms 到 CSV，并生成 Markdown 报告。`
- [todo] `请为 network_cost_model 增加单元测试（C++ + Python），覆盖 LAN/WAN 预设、参数覆盖、all-to-all 公式和边界输入。`
