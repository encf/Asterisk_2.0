#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "key_manager.h"
#include "../io/netmp.h"
#include "../utils/circuit.h"
#include "../utils/types.h"

namespace asterisk2 {

using common::utils::Field;
using common::utils::FIn2Gate;
using common::utils::LevelOrderedCircuit;
using common::utils::wire_t;

struct TripleShare {
  Field a;
  Field b;
  Field c;
};

struct MulAuthTupleShare {
  Field a_prime;
  Field b_prime;
  Field c_prime;
  Field a_prime_b_prime;
  Field a_prime_c_prime;
  Field b_prime_c_prime;
  Field a_prime_b_prime_c_prime;
};

struct MulOfflineData {
  std::vector<TripleShare> triples;
  std::vector<MulAuthTupleShare> auth_tuples;
  // Malicious-mode bootstrap material (additive shares among computing parties).
  // In semi-honest mode these remain zero.
  Field delta_share{Field(0)};
  Field delta_inv_share{Field(0)};
  // Helper-only plaintext MAC key material (not shared with computing parties).
  Field helper_delta{Field(0)};
  Field helper_delta_inv{Field(0)};
  bool ready{false};
};

struct TruncOfflineData {
  size_t ell_x{0};
  size_t m{0};
  size_t s{0};
  std::vector<Field> r_share;
  std::vector<Field> r0_share;
  // Malicious-mode authenticated masks.
  std::vector<Field> delta_r_share;
  std::vector<Field> delta_r0_share;
  Field delta_share{Field(0)};
  bool ready{false};
};

struct AuthTruncResult {
  std::vector<Field> trunc_x_shares;
  std::vector<Field> trunc_delta_x_shares;
};

struct BatchedTruncOfflineData {
  size_t lx{0};
  size_t s{0};
  std::vector<Field> r_share;
  std::vector<Field> r0_share;
  bool ready{false};
};

struct CompareMaskData {
  std::vector<Field> rho;
  std::vector<size_t> permutation;
  bool t{false};
  bool ready{false};
};

struct CompareOfflineData {
  BatchedTruncOfflineData trunc_data;
  CompareMaskData cmp_data;
  bool ready{false};
};

struct CompareOfflineDataMalicious {
  size_t lx{0};
  size_t s{0};
  std::vector<Field> r_share;
  std::vector<Field> r0_share;
  std::vector<Field> delta_r_share;
  std::vector<Field> delta_r0_share;
  Field delta_share{Field(0)};
  CompareMaskData cmp_data;
  bool ready{false};
};

struct AuthCompareResult {
  Field gtez_share{Field(0)};
  Field delta_gtez_share{Field(0)};
};

enum class SecurityModel {
  kSemiHonest,
  kMalicious,
};

struct ProtocolConfig {
  SecurityModel security_model{SecurityModel::kSemiHonest};
  // Enable parallel peer send/recv in each communication step.
  bool parallel_send{false};
  // TODO(malicious): move pairwise/shared-key generation to Asterisk-style
  // key management (see asterisk::OfflineEvaluator::keyGen) when adding
  // maliciously secure preprocessing.
};

struct BGTEZStats {
  size_t batched_open_calls{0};
};

struct OnlineTimingStats {
  double local_compute_ms{0.0};
  double network_overhead_ms{0.0};
  bool ready{false};
};

struct MaliciousInputShareData {
  std::unordered_map<wire_t, Field> x_shares;
  std::unordered_map<wire_t, Field> delta_x_shares;
};

class Protocol {
 public:
  Protocol(int nP, int id, std::shared_ptr<io::NetIOMP> network,
           LevelOrderedCircuit circ, int seed = 200,
           ProtocolConfig config = {});

  MulOfflineData mul_offline();
  std::vector<Field> mul_online(const std::unordered_map<wire_t, Field>& inputs,
                                const MulOfflineData& offline_data);
  TruncOfflineData trunc_offline(size_t batch_size, size_t ell_x, size_t m, size_t s);
  TruncOfflineData trunc_offline_malicious(size_t batch_size, size_t ell_x, size_t m, size_t s);
  std::vector<Field> trunc_online(const std::vector<Field>& x_shares,
                                  const TruncOfflineData& offline_data);
  AuthTruncResult trunc_online_malicious(const std::vector<Field>& x_shares,
                                         const std::vector<Field>& delta_x_shares,
                                         const TruncOfflineData& offline_data);
  CompareOfflineData compare_offline(size_t lx, size_t s,
                                     bool force_t = false, bool forced_t_value = false);
  Field compare_online(const Field& x_share, const CompareOfflineData& offline_data,
                       BGTEZStats* stats = nullptr);
  CompareOfflineDataMalicious compare_offline_malicious(size_t lx, size_t s,
                                                        bool force_t = false,
                                                        bool forced_t_value = false);
  AuthCompareResult compare_online_malicious(
      const Field& x_share, const Field& delta_x_share,
      const CompareOfflineDataMalicious& offline_data);

  std::vector<TripleShare> offline();

  std::vector<Field> online(const std::unordered_map<wire_t, Field>& inputs,
                            const std::vector<TripleShare>& triples);
  std::vector<Field> onlineSemiHonestForBenchmark(
      const std::unordered_map<wire_t, Field>& inputs,
      const std::vector<TripleShare>& triples);
  std::vector<Field> probabilisticTruncate(const std::vector<Field>& x_shares,
                                           size_t ell_x, size_t m,
                                           size_t s);
  std::vector<Field> batchedTruncateAll(const Field& x_share, size_t lx, size_t s,
                                        BGTEZStats* stats = nullptr);
  std::vector<Field> serialTruncateAllForTesting(const Field& x_share, size_t lx, size_t s,
                                                 BGTEZStats* stats = nullptr);
  Field bgtezCompare(const Field& x_share, size_t lx, size_t s,
                    bool force_t = false, bool forced_t_value = false,
                    BGTEZStats* stats = nullptr);
  OnlineTimingStats onlineTimingStats() const { return online_timing_stats_; }
  MaliciousInputShareData maliciousInputShareForTesting(
      const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data);

 private:
  Field openToComputingParties(const Field& local_share) const;
  std::vector<Field> openVectorToComputingParties(const std::vector<Field>& local_vec) const;
  MulOfflineData mul_offline_semi_honest(const std::vector<FIn2Gate>& mul_gates);
  MulOfflineData mul_offline_malicious(const std::vector<FIn2Gate>& mul_gates);
  std::vector<Field> mul_online_semi_honest(
      const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data);
  std::vector<Field> mul_online_malicious(
      const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data);
  MaliciousInputShareData buildMaliciousInputShares(
      const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data);
  void verifyMaliciousKeyMaterial(const MulOfflineData& offline_data) const;
  std::vector<std::vector<Field>> recvFieldVectorsFromPeers(const std::vector<int>& peers,
                                                            size_t len) const;
  void sendFieldVectorToPeers(const std::vector<int>& peers, const std::vector<Field>& data) const;
  std::vector<int> computingPeerIdsExcludingSelf() const;
  void initializeMaliciousMacSetup();

  int nP_;
  int id_;
  int helper_id_;
  int seed_;
  KeyManager key_manager_;
  ProtocolConfig config_;
  std::shared_ptr<io::NetIOMP> network_;
  LevelOrderedCircuit circ_;
  std::vector<Field> wire_share_;
  OnlineTimingStats online_timing_stats_;
  bool malicious_mac_setup_ready_{false};
  Field malicious_delta_share_{Field(0)};
  Field malicious_delta_inv_share_{Field(0)};
  Field helper_delta_{Field(0)};
  Field helper_delta_inv_{Field(0)};
};

}  // namespace asterisk2
