#pragma once

#include <memory>
#include <unordered_map>

#include "../io/netmp.h"
#include "../utils/circuit.h"
#include "../utils/types.h"
#include "protocol.h"

namespace asterisk2 {

using common::utils::Field;
using common::utils::FIn1Gate;
using common::utils::FIn2Gate;
using common::utils::GateType;
using common::utils::LevelOrderedCircuit;
using common::utils::wire_t;

struct SemiHonestAppOfflineData {
  std::unordered_map<wire_t, MulOfflineData> mul_gates;
  std::unordered_map<wire_t, CompareOfflineData> compare_gates;
  std::unordered_map<wire_t, EqzOfflineData> eqz_gates;
  bool ready{false};
};

struct MaliciousAppOfflineData {
  MulOfflineData input_auth;
  std::unordered_map<wire_t, MulOfflineData> mul_gates;
  std::unordered_map<wire_t, CompareOfflineDataMalicious> compare_gates;
  std::unordered_map<wire_t, EqzOfflineDataMalicious> eqz_gates;
  Field delta_share{Field(0)};
  bool ready{false};
};

class SemiHonestAppEvaluator {
 public:
  SemiHonestAppEvaluator(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                         LevelOrderedCircuit circ, int seed = 200);

  SemiHonestAppOfflineData offline(size_t lx, size_t slack);
  std::vector<Field> online(const std::unordered_map<wire_t, Field>& inputs,
                            const SemiHonestAppOfflineData& offline_data);
  std::vector<Field> onlineBatched(const std::unordered_map<wire_t, Field>& inputs,
                                   const SemiHonestAppOfflineData& offline_data);

 private:
  static LevelOrderedCircuit singleMulCircuit();
  static LevelOrderedCircuit emptyCircuit();
  int gateSeed(wire_t wid, int slot = 0) const;

  int nP_;
  int id_;
  int seed_;
  std::shared_ptr<io::NetIOMP> network_;
  LevelOrderedCircuit circ_;
  std::vector<Field> wire_share_;
};

class MaliciousAppEvaluator {
 public:
  MaliciousAppEvaluator(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                        LevelOrderedCircuit circ, int seed = 200);

  MaliciousAppOfflineData offline(size_t lx, size_t slack);
  std::vector<Field> online(const std::unordered_map<wire_t, Field>& inputs,
                            const MaliciousAppOfflineData& offline_data);
  std::vector<Field> onlineBatched(const std::unordered_map<wire_t, Field>& inputs,
                                   const MaliciousAppOfflineData& offline_data);
  std::vector<Field> deltaOutputs() const;

 private:
  static LevelOrderedCircuit singleMulCircuit();
  static LevelOrderedCircuit emptyCircuit();
  int gateSeed(wire_t wid, int slot = 0) const;

  int nP_;
  int id_;
  int seed_;
  std::shared_ptr<io::NetIOMP> network_;
  LevelOrderedCircuit circ_;
  std::vector<Field> wire_share_;
  std::vector<Field> delta_wire_share_;
  std::unique_ptr<Protocol> input_proto_;
  std::unique_ptr<Protocol> mul_proto_;
  std::unique_ptr<Protocol> cmp_proto_;
};

}  // namespace asterisk2
