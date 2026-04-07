#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

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

enum class SecurityModel {
  kSemiHonest,
  kMalicious,
};

struct ProtocolConfig {
  SecurityModel security_model{SecurityModel::kSemiHonest};
  // Simulated network latency per communication step in milliseconds.
  double sim_latency_ms{0.0};
  // Simulated bandwidth cap in megabits per second (<=0 disables).
  double sim_bandwidth_mbps{0.0};
  // Enable parallel peer send/recv in each communication step.
  bool parallel_send{false};
  // TODO(malicious): move pairwise/shared-key generation to Asterisk-style
  // key management (see asterisk::OfflineEvaluator::keyGen) when adding
  // maliciously secure preprocessing.
};

class Protocol {
 public:
  Protocol(int nP, int id, std::shared_ptr<io::NetIOMP> network,
           LevelOrderedCircuit circ, int seed = 200,
           ProtocolConfig config = {});

  std::vector<TripleShare> offline();

  std::vector<Field> online(const std::unordered_map<wire_t, Field>& inputs,
                            const std::vector<TripleShare>& triples);

 private:
  struct OpenPair {
    Field d;
    Field e;
  };

  std::vector<OpenPair> openPairsToComputingParties(
      const std::vector<OpenPair>& local_pairs) const;
  void maybeSimulateStep(size_t aggregate_bytes) const;
  void maybeSimulateLatency() const;
  void maybeSimulateBandwidth(size_t bytes) const;

  int nP_;
  int id_;
  int helper_id_;
  int seed_;
  ProtocolConfig config_;
  std::shared_ptr<io::NetIOMP> network_;
  LevelOrderedCircuit circ_;
  std::vector<Field> wire_share_;
};

}  // namespace asterisk2
