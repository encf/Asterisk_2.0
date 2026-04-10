# Asterisk2.0 恶意安全实现任务分解（文件/函数级）

> 目标：将 `SecurityModel::kMalicious` 从“占位”升级为可运行、可验证、可基准测试的完整流程。  
> 范围：`src/Asterisk2.0/`、`benchmarks/`、`test/`、`README.md`。

## 实施进度（持续更新）

- ✅ Phase 1 bootstrap 已落地：`mul_offline()` 在 malicious 模式不再直接抛异常。
- ✅ 已新增 malicious 模式乘法冒烟测试：`test/asterisk2_multiplication.cpp` 中 `malicious_mode_mul_roundtrip_smoke`。
- ✅ semi-honest 与 malicious 乘法路径已在代码层分离（`mul_offline_semi_honest/mul_offline_malicious` 与 `mul_online_semi_honest/mul_online_malicious`）。
- ✅ `mul_online_malicious` 已接入 `runMacSetupDH` 生成的 `[Δ]` 与 `[Δ^{-1}]` 一致性校验（计算方打开并校验 `Δ * Δ^{-1} = 1`）。
- ✅ 新增输出一致性校验回路：helper 从计算方输出 share 重构结果并回传，计算方与本地 batched-open 重构结果比对。
- ✅ `Pi_MACSetup-DH` 已按独立模块实现：`src/Asterisk2.0/mac_setup.h/.cpp`，并新增 `asterisk2_mac_setup_dh_test` 覆盖核心不变量。
- ✅ 已实现显式会话级密钥管理模块：`src/Asterisk2.0/key_manager.h/.cpp`，`Pi_MACSetup-DH` 改为从 key manager 读取 helper<->party pairwise keys。
- ✅ `runMacSetupDH` 不再在函数内部创建/管理密钥，统一改为由调用方显式传入 `KeyManager`。
- ✅ semi-honest 离线 share 派生（mul/trunc/compare）已接入 key manager，不再直接用 `(seed, party_id)` 在协议逻辑内拼“隐式密钥”；其中 compare 离线共享掩码改为使用仅计算方共享的 `K_P`。
- ✅ 已实现 malicious 输入认证分享原语（`x' = x + r + t`、helper 侧补足 share、计算方本地去 mask）；一致性检查由测试用例覆盖。
- ✅ malicious 乘法离线预处理已扩展为“算术三元组 + MAC-layer 辅助 tuple”批量生成：`[a],[b],[ab]` 与 `[a'],[b'],[c'],[a'b'],[a'c'],[b'c'],[a'b'c']`。
- ⏳ Ver-DH、deferred batch verify 与 fair release 尚未接入（后续阶段实现）。

## 0. 当前基线（必须先确认）

- 现状（已更新）：`mul_offline()` / `mul_online()` 在 malicious 模式已具备可运行分派路径，不再直接抛异常；当前仍缺 Ver-DH、deferred batch verify、fair release 与 trunc/compare 的 malicious 专属验证链路。
- 参考入口：
  - `src/Asterisk2.0/protocol.h`
  - `src/Asterisk2.0/protocol.cpp`
  - `benchmarks/asterisk2_mpc.cpp`
  - `benchmarks/asterisk2_bgtez.cpp`

## 1) 认证分享层（Authenticated Sharing）

### 1.1 新增数据结构（`protocol.h`）

新增建议结构（命名可微调，但语义应保持一致）：

- `struct AuthShare { Field x; Field dx; };`
- `struct AuthKeyShare { Field delta; Field delta_inv; bool ready; };`
- `struct VerifyTuple { Field x; Field dx; Field v; };`
- `struct DeferredVerifyState { std::vector<VerifyTuple> pending; bool ready; };`

并在 `Protocol` 私有成员新增：

- `AuthKeyShare auth_key_share_;`
- `DeferredVerifyState deferred_verify_;`

### 1.2 新增 helper/compute 侧认证输入接口（`protocol.h/.cpp`）

新增（或等价）私有函数：

- `AuthKeyShare initAuthKeyShare();`
- `AuthShare inputShareAuthenticated(Field local_input, uint64_t input_idx);`
- `void ensureAuthReady();`

实现要点：

- helper 生成 `Δ` 与 `Δ^{-1}` 的加法分享；
- 输入分享按 `x' = x + r + t` 风格执行；
- 保持不变量 `sum(dx_i) = Δ * sum(x_i)`。

## 2) 挑战与验证协议（Chal-DH / Ver-DH）

### 2.1 挑战生成（`protocol.cpp`）

新增：

- `Field genChallengeV(uint64_t idx);`（helper 明文、计算方分享）

要求：

- 使用当前风格的共享密钥 PRG 派生（不要引入非确定随机源）。

### 2.2 单次验证与批量验证

新增：

- `bool verifyOne(const VerifyTuple& item);`
- `bool flushDeferredVerify();`（批量触发）
- `void enqueueVerify(const Field& x, const Field& dx);`

流程：

1. 先重构 `x + v`。
2. 计算方发送 `t_i = Δ_i(x+v) - (Δx)_i` 给 helper。
3. helper 校验 `sum(t_i) == Δ*v`。
4. 失败则返回 false 并触发上层 abort。

## 3) 公平输出释放（Fair Release）

### 3.1 输出释放接口（`protocol.h/.cpp`）

新增（或等价）接口：

- `std::vector<Field> releaseOutputsFair(const std::vector<AuthShare>& auth_outputs);`

策略：

- 先开 `x+v`，后验证；
- 仅在验证成功时 helper 广播 `v`；
- 任何失败场景必须保证“无人获得最终输出”。

## 4) 恶意乘法（Mul-DH）

### 4.1 离线阶段扩展（`MulOfflineData`）

在 `protocol.h` 中扩展离线结构，至少包含：

- 普通三元组 `[a],[b],[ab]`
- 认证辅助 tuple：`[a'], [b'], [c'], [a'b'], [a'c'], [b'c'], [a'b'c']`

并拆分实现函数：

- `MulOfflineData mul_offline_semi_honest();`
- `MulOfflineData mul_offline_malicious();`

`mul_offline()` 只做分派，不直接承载全部逻辑。

### 4.2 在线阶段恶意路径

新增：

- `std::vector<Field> mul_online_malicious(...);`
- 以及内部 AuthShare 版本乘法内核（建议函数化）。

实现：

- 打开 `d,e,dΔ,eΔ,f`；
- 本地组装 `[xy]` 和 `[Δxy]`；
- 将结果加入 `deferred_verify_` 队列，段尾统一验证。

## 5) 截断与比较的认证升级

### 5.1 截断（`trunc_*` / `batchedTruncateAll`）

将 trunc 系列接口由“仅值分享”升级为“值+MAC”双轨计算：

- `trunc_online_malicious(...)`（或在现函数内分派）
- `batchedTruncateAll_malicious(...)`

要求：

- 公开值步骤全部纳入 `enqueueVerify`；
- 结果在 release 前通过批量验证。

### 5.2 比较（`bgtezCompare` / `compare_*`）

升级为认证版本：

- 比较中间开值进入 deferred verify；
- 输出 bit 进入认证 release 通道。

## 6) 验证调度器与阶段边界

在 `Protocol` 中明确三个阶段接口：

1. `optimistic online`
2. `deferred verification`
3. `fair release`

建议新增：

- `void beginOnlineSegment();`
- `bool endOnlineSegmentAndVerify();`

用于 benchmark 与测试中的稳定复用。

## 7) Benchmark 改造

## 7.1 `benchmarks/asterisk2_mpc.cpp`

新增 malicious 模式统计字段：

- `online_optimistic_ms`
- `deferred_verify_ms`
- `release_ms`
- `total_ms`

并在 JSON 输出中保留与 semi-honest 可对照字段。

## 7.2 `benchmarks/asterisk2_bgtez.cpp`

同样输出上述分项；比较协议单独记录：

- `verify_calls`
- `verify_failures`

## 8) 测试矩阵（最小必需）

在 `test/` 新增（建议）文件：

- `test/asterisk2_malicious_auth.cpp`
- `test/asterisk2_malicious_mul.cpp`
- `test/asterisk2_malicious_trunc_compare.cpp`
- `test/asterisk2_malicious_release.cpp`

覆盖点：

1. `sum(dx_i) == Δ * sum(x_i)` 不变量；
2. Ver-DH 正例与篡改反例；
3. Mul-DH 正确性与检测能力；
4. deferred verify 可在段尾抓到在线篡改；
5. 验证失败时公平释放（无人得到输出）；
6. trunc/compare 的 malicious 正确性。

## 9) 文档同步（必须）

- 在 `README.md` 增补 malicious 的三阶段语义说明；
- 说明 helper 信任边界与 abort 行为；
- 增加 benchmark 统计口径说明，避免 offline/online 混淆。

## 10) 里程碑与验收

- **M1**：认证输入 + Ver-DH 跑通，`kMalicious` 不再抛异常。
- **M2**：Mul-DH 正确且可检测篡改（deferred verify）。
- **M3**：trunc/compare 在 malicious 下跑通并走公平释放。
- **M4**：benchmark 分项齐全，新增测试全部通过。

---

## 实施建议（工程化）

- 保持 semi-honest 路径零回归：所有 malicious 逻辑以分派函数隔离；
- 每个阶段单独提交：`auth -> verify -> mul -> trunc/compare -> benchmark/tests/docs`；
- 每阶段必须附带可执行测试命令与结果。
