#include "app_evaluator.h"

#include <string>
#include <stdexcept>

namespace asterisk2 {

namespace {

LevelOrderedCircuit buildSingleMulCircuit() {
  common::utils::Circuit<Field> circ;
  auto in1 = circ.newInputWire();
  auto in2 = circ.newInputWire();
  auto out = circ.addGate(GateType::kMul, in1, in2);
  circ.setAsOutput(out);
  return circ.orderGatesByLevel();
}

LevelOrderedCircuit buildEmptyCircuit() {
  common::utils::Circuit<Field> circ;
  return circ.orderGatesByLevel();
}

uint64_t appDomainTag(wire_t wid, uint64_t slot) {
  return (static_cast<uint64_t>(wid) << 8) | slot;
}

}  // namespace

SemiHonestAppEvaluator::SemiHonestAppEvaluator(int nP, int id,
                                               std::shared_ptr<io::NetIOMP> network,
                                               LevelOrderedCircuit circ, int seed)
    : nP_(nP),
      id_(id),
      seed_(seed),
      network_(std::move(network)),
      circ_(std::move(circ)),
      wire_share_(circ_.num_gates, Field(0)) {}

LevelOrderedCircuit SemiHonestAppEvaluator::singleMulCircuit() { return buildSingleMulCircuit(); }

LevelOrderedCircuit SemiHonestAppEvaluator::emptyCircuit() { return buildEmptyCircuit(); }

int SemiHonestAppEvaluator::gateSeed(wire_t wid, int slot) const {
  return seed_ + static_cast<int>(4 * wid + slot);
}

SemiHonestAppOfflineData SemiHonestAppEvaluator::offline(size_t lx, size_t slack) {
  SemiHonestAppOfflineData out;
  const auto mul_circ = singleMulCircuit();
  const auto empty_circ = emptyCircuit();

  for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      switch (gate->type) {
        case GateType::kMul: {
          Protocol proto(nP_, id_, network_, mul_circ, gateSeed(gate->out));
          out.mul_gates.emplace(gate->out, proto.mul_offline());
          break;
        }
        case GateType::kLtz: {
          Protocol proto(nP_, id_, network_, empty_circ, seed_);
          out.compare_gates.emplace(gate->out,
                                     proto.compare_offline_tagged(lx, slack,
                                                                  appDomainTag(gate->out, 1)));
          break;
        }
        case GateType::kEqz: {
          Protocol proto(nP_, id_, network_, empty_circ, seed_);
          out.eqz_gates.emplace(gate->out,
                                proto.eqz_offline_tagged(lx, slack,
                                                         appDomainTag(gate->out, 3)));
          break;
        }
        case GateType::kInp:
        case GateType::kAdd:
        case GateType::kSub:
        case GateType::kConstAdd:
        case GateType::kConstMul:
          break;
        default:
          throw std::runtime_error("SemiHonestAppEvaluator encountered unsupported gate type");
      }
    }
  }

  out.ready = true;
  return out;
}

std::vector<Field> SemiHonestAppEvaluator::online(
    const std::unordered_map<wire_t, Field>& inputs,
    const SemiHonestAppOfflineData& offline_data) {
  if (!offline_data.ready) {
    throw std::runtime_error("SemiHonestAppEvaluator requires ready offline data");
  }

  std::fill(wire_share_.begin(), wire_share_.end(), Field(0));
  const auto mul_circ = singleMulCircuit();
  const auto empty_circ = emptyCircuit();

  for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      switch (gate->type) {
        case GateType::kInp: {
          auto it = inputs.find(gate->out);
          wire_share_[gate->out] = (it == inputs.end()) ? Field(0) : it->second;
          break;
        }
        case GateType::kAdd: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] + wire_share_[g->in2];
          break;
        }
        case GateType::kSub: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] - wire_share_[g->in2];
          break;
        }
        case GateType::kConstAdd: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] + ((id_ == 0) ? g->cval : Field(0));
          break;
        }
        case GateType::kConstMul: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] * g->cval;
          break;
        }
        case GateType::kMul: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          auto it = offline_data.mul_gates.find(g->out);
          if (it == offline_data.mul_gates.end()) {
            throw std::runtime_error("Missing mul offline data for application gate");
          }
          Protocol proto(nP_, id_, network_, mul_circ, gateSeed(g->out));
          std::unordered_map<wire_t, Field> mul_inputs = {
              {0, wire_share_[g->in1]},
              {1, wire_share_[g->in2]},
          };
          auto outputs = proto.mul_online(mul_inputs, it->second);
          if (id_ >= nP_) {
            wire_share_[g->out] = Field(0);
            break;
          }
          if (outputs.size() != 1) {
            throw std::runtime_error("Unexpected mul application output arity");
          }
          wire_share_[g->out] = outputs[0];
          break;
        }
        case GateType::kLtz: {
          auto* g = static_cast<FIn1Gate*>(gate.get());
          auto cmp_it = offline_data.compare_gates.find(g->out);
          if (cmp_it == offline_data.compare_gates.end()) {
            throw std::runtime_error("Missing compare offline data for application gate");
          }
          Protocol proto(nP_, id_, network_, empty_circ, seed_);
          const Field gtez_share = proto.compare_online(wire_share_[g->in], cmp_it->second);
          const Field one_share = (id_ == 0) ? Field(1) : Field(0);
          wire_share_[g->out] = one_share - gtez_share;
          break;
        }
        case GateType::kEqz: {
          auto* g = static_cast<FIn1Gate*>(gate.get());
          auto it = offline_data.eqz_gates.find(g->out);
          if (it == offline_data.eqz_gates.end()) {
            throw std::runtime_error("Missing EQZ offline data for application gate");
          }
          Protocol proto(nP_, id_, network_, empty_circ, seed_);
          wire_share_[g->out] = proto.eqz_online(wire_share_[g->in], it->second);
          break;
        }
        default:
          throw std::runtime_error("SemiHonestAppEvaluator encountered unsupported gate type");
      }
    }
  }

  std::vector<Field> outputs;
  outputs.reserve(circ_.outputs.size());
  for (auto wid : circ_.outputs) {
    outputs.push_back(wire_share_[wid]);
  }
  return outputs;
}

std::vector<Field> SemiHonestAppEvaluator::onlineBatched(
    const std::unordered_map<wire_t, Field>& inputs,
    const SemiHonestAppOfflineData& offline_data) {
  if (!offline_data.ready) {
    throw std::runtime_error("SemiHonestAppEvaluator requires ready offline data");
  }

  std::fill(wire_share_.begin(), wire_share_.end(), Field(0));
  Protocol mul_proto(nP_, id_, network_, singleMulCircuit(), seed_);
  Protocol cmp_proto(nP_, id_, network_, emptyCircuit(), seed_);

  for (const auto& level : circ_.gates_by_level) {
    std::vector<const FIn2Gate*> mul_gates;
    std::vector<const FIn1Gate*> ltz_gates;
    std::vector<const FIn1Gate*> eqz_gates;

    for (const auto& gate : level) {
      switch (gate->type) {
        case GateType::kInp: {
          auto it = inputs.find(gate->out);
          wire_share_[gate->out] = (it == inputs.end()) ? Field(0) : it->second;
          break;
        }
        case GateType::kAdd: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] + wire_share_[g->in2];
          break;
        }
        case GateType::kSub: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] - wire_share_[g->in2];
          break;
        }
        case GateType::kConstAdd: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] + ((id_ == 0) ? g->cval : Field(0));
          break;
        }
        case GateType::kConstMul: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] * g->cval;
          break;
        }
        case GateType::kMul:
          mul_gates.push_back(static_cast<FIn2Gate*>(gate.get()));
          break;
        case GateType::kLtz:
          ltz_gates.push_back(static_cast<FIn1Gate*>(gate.get()));
          break;
        case GateType::kEqz:
          eqz_gates.push_back(static_cast<FIn1Gate*>(gate.get()));
          break;
        default:
          throw std::runtime_error("SemiHonestAppEvaluator encountered unsupported gate type");
      }
    }

    if (!mul_gates.empty()) {
      std::vector<Field> x_shares;
      std::vector<Field> y_shares;
      std::vector<const MulOfflineData*> offline_vec;
      x_shares.reserve(mul_gates.size());
      y_shares.reserve(mul_gates.size());
      offline_vec.reserve(mul_gates.size());
      for (const auto* g : mul_gates) {
        auto it = offline_data.mul_gates.find(g->out);
        if (it == offline_data.mul_gates.end()) {
          throw std::runtime_error("Missing mul offline data for application gate");
        }
        x_shares.push_back(wire_share_[g->in1]);
        y_shares.push_back(wire_share_[g->in2]);
        offline_vec.push_back(&it->second);
      }
      const auto mul_out = mul_proto.mul_online_semi_honest_batch(x_shares, y_shares, offline_vec);
      for (size_t i = 0; i < mul_gates.size(); ++i) {
        wire_share_[mul_gates[i]->out] = (id_ < nP_) ? mul_out[i] : Field(0);
      }
    }

    if (!ltz_gates.empty()) {
      std::vector<Field> x_shares;
      std::vector<const CompareOfflineData*> offline_vec;
      x_shares.reserve(ltz_gates.size());
      offline_vec.reserve(ltz_gates.size());
      for (const auto* g : ltz_gates) {
        auto it = offline_data.compare_gates.find(g->out);
        if (it == offline_data.compare_gates.end()) {
          throw std::runtime_error("Missing compare offline data for application gate");
        }
        x_shares.push_back(wire_share_[g->in]);
        offline_vec.push_back(&it->second);
      }
      const auto gtez_shares = cmp_proto.compare_online_batch(x_shares, offline_vec);
      for (size_t i = 0; i < ltz_gates.size(); ++i) {
        const Field one_share = (id_ == 0) ? Field(1) : Field(0);
        wire_share_[ltz_gates[i]->out] = one_share - gtez_shares[i];
      }
    }

    if (!eqz_gates.empty()) {
      std::vector<Field> x_shares;
      std::vector<const EqzOfflineData*> offline_vec;
      x_shares.reserve(eqz_gates.size());
      offline_vec.reserve(eqz_gates.size());
      for (const auto* g : eqz_gates) {
        auto it = offline_data.eqz_gates.find(g->out);
        if (it == offline_data.eqz_gates.end()) {
          throw std::runtime_error("Missing EQZ offline data for application gate");
        }
        x_shares.push_back(wire_share_[g->in]);
        offline_vec.push_back(&it->second);
      }
      const auto eqz_out = cmp_proto.eqz_online_batch(x_shares, offline_vec);
      for (size_t i = 0; i < eqz_gates.size(); ++i) {
        wire_share_[eqz_gates[i]->out] = eqz_out[i];
      }
    }
  }

  std::vector<Field> outputs;
  outputs.reserve(circ_.outputs.size());
  for (auto wid : circ_.outputs) {
    outputs.push_back(wire_share_[wid]);
  }
  return outputs;
}

MaliciousAppEvaluator::MaliciousAppEvaluator(int nP, int id,
                                             std::shared_ptr<io::NetIOMP> network,
                                             LevelOrderedCircuit circ, int seed)
    : nP_(nP),
      id_(id),
      seed_(seed),
      network_(std::move(network)),
      circ_(std::move(circ)),
      wire_share_(circ_.num_gates, Field(0)),
      delta_wire_share_(circ_.num_gates, Field(0)) {}

LevelOrderedCircuit MaliciousAppEvaluator::singleMulCircuit() { return buildSingleMulCircuit(); }

LevelOrderedCircuit MaliciousAppEvaluator::emptyCircuit() { return buildEmptyCircuit(); }

int MaliciousAppEvaluator::gateSeed(wire_t wid, int slot) const {
  return seed_ + static_cast<int>(4 * wid + slot);
}

MaliciousAppOfflineData MaliciousAppEvaluator::offline(size_t lx, size_t slack) {
  MaliciousAppOfflineData out;

  ProtocolConfig cfg;
  cfg.security_model = SecurityModel::kMalicious;

  if (!input_proto_) {
    input_proto_ = std::make_unique<Protocol>(nP_, id_, network_, circ_, seed_, cfg);
  }
  if (!mul_proto_) {
    mul_proto_ = std::make_unique<Protocol>(nP_, id_, network_, singleMulCircuit(), seed_, cfg);
  }
  if (!cmp_proto_) {
    cmp_proto_ = std::make_unique<Protocol>(nP_, id_, network_, emptyCircuit(), seed_, cfg);
  }

  {
    out.input_auth = mul_proto_->mul_offline();
    if (id_ < nP_) {
      out.delta_share = out.input_auth.delta_share;
    }
  }

  for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      switch (gate->type) {
        case GateType::kMul: {
          out.mul_gates.emplace(gate->out, mul_proto_->mul_offline());
          break;
        }
        case GateType::kLtz: {
          out.compare_gates.emplace(
              gate->out,
              cmp_proto_->compare_offline_malicious_tagged(
                  lx, slack, appDomainTag(gate->out, 1)));
          break;
        }
        case GateType::kEqz: {
          out.eqz_gates.emplace(
              gate->out,
              cmp_proto_->eqz_offline_malicious_tagged(lx, slack, appDomainTag(gate->out, 3)));
          break;
        }
        case GateType::kInp:
        case GateType::kAdd:
        case GateType::kSub:
        case GateType::kConstAdd:
        case GateType::kConstMul:
        default:
          break;
      }
    }
  }

  out.ready = true;
  return out;
}

std::vector<Field> MaliciousAppEvaluator::online(
    const std::unordered_map<wire_t, Field>& inputs,
    const MaliciousAppOfflineData& offline_data) {
  if (!offline_data.ready) {
    throw std::runtime_error("MaliciousAppEvaluator requires ready offline data");
  }

  std::fill(wire_share_.begin(), wire_share_.end(), Field(0));
  std::fill(delta_wire_share_.begin(), delta_wire_share_.end(), Field(0));
  if (!input_proto_ || !mul_proto_ || !cmp_proto_) {
    throw std::runtime_error(
        "MaliciousAppEvaluator.online requires offline() to initialize protocol state");
  }

  {
    auto auth_inputs = input_proto_->maliciousInputShareForTesting(inputs, offline_data.input_auth);
    for (const auto& [w, x] : auth_inputs.x_shares) {
      wire_share_[w] = x;
    }
    for (const auto& [w, dx] : auth_inputs.delta_x_shares) {
      delta_wire_share_[w] = dx;
    }
  }

  for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      switch (gate->type) {
        case GateType::kInp:
          break;
        case GateType::kAdd: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] + wire_share_[g->in2];
          delta_wire_share_[g->out] = delta_wire_share_[g->in1] + delta_wire_share_[g->in2];
          break;
        }
        case GateType::kSub: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] - wire_share_[g->in2];
          delta_wire_share_[g->out] = delta_wire_share_[g->in1] - delta_wire_share_[g->in2];
          break;
        }
        case GateType::kConstAdd: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] + ((id_ == 0) ? g->cval : Field(0));
          if (id_ < nP_) {
            delta_wire_share_[g->out] =
                delta_wire_share_[g->in] + offline_data.delta_share * g->cval;
          }
          break;
        }
        case GateType::kConstMul: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] * g->cval;
          delta_wire_share_[g->out] = delta_wire_share_[g->in] * g->cval;
          break;
        }
        case GateType::kMul: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          auto it = offline_data.mul_gates.find(g->out);
          if (it == offline_data.mul_gates.end()) {
            throw std::runtime_error("Missing malicious mul offline data for application gate");
          }
          auto out = mul_proto_->mul_online_malicious_single(
              wire_share_[g->in1], delta_wire_share_[g->in1],
              wire_share_[g->in2], delta_wire_share_[g->in2], it->second);
          if (id_ >= nP_) {
            wire_share_[g->out] = Field(0);
            delta_wire_share_[g->out] = Field(0);
            break;
          }
          wire_share_[g->out] = out.share;
          delta_wire_share_[g->out] = out.delta_share;
          break;
        }
        case GateType::kLtz: {
          auto* g = static_cast<FIn1Gate*>(gate.get());
          auto it = offline_data.compare_gates.find(g->out);
          if (it == offline_data.compare_gates.end()) {
            throw std::runtime_error("Missing malicious compare offline data for application gate");
          }
          AuthCompareResult out;
          try {
            out = cmp_proto_->compare_online_malicious(wire_share_[g->in],
                                                       delta_wire_share_[g->in],
                                                       it->second);
          } catch (const std::exception& ex) {
            throw std::runtime_error("MaliciousAppEvaluator LTZ gate " +
                                     std::to_string(g->out) + " failed: " + ex.what());
          }
          const Field one_share = (id_ == 0) ? Field(1) : Field(0);
          wire_share_[g->out] = one_share - out.gtez_share;
          delta_wire_share_[g->out] = it->second.delta_share - out.delta_gtez_share;
          break;
        }
        case GateType::kEqz: {
          auto* g = static_cast<FIn1Gate*>(gate.get());
          auto it = offline_data.eqz_gates.find(g->out);
          if (it == offline_data.eqz_gates.end()) {
            throw std::runtime_error("Missing malicious EQZ offline data for application gate");
          }
          AuthEqzResult out;
          try {
            out = cmp_proto_->eqz_online_malicious(wire_share_[g->in],
                                                   delta_wire_share_[g->in],
                                                   it->second);
          } catch (const std::exception& ex) {
            throw std::runtime_error("MaliciousAppEvaluator EQZ gate " +
                                     std::to_string(g->out) + " failed: " + ex.what());
          }
          wire_share_[g->out] = out.eqz_share;
          delta_wire_share_[g->out] = out.delta_eqz_share;
          break;
        }
        default:
          throw std::runtime_error("MaliciousAppEvaluator encountered unsupported gate type");
      }
    }
  }

  std::vector<Field> outputs;
  outputs.reserve(circ_.outputs.size());
  for (auto wid : circ_.outputs) {
    outputs.push_back(wire_share_[wid]);
  }
  return outputs;
}

std::vector<Field> MaliciousAppEvaluator::onlineBatched(
    const std::unordered_map<wire_t, Field>& inputs,
    const MaliciousAppOfflineData& offline_data) {
  if (!offline_data.ready) {
    throw std::runtime_error("MaliciousAppEvaluator requires ready offline data");
  }

  std::fill(wire_share_.begin(), wire_share_.end(), Field(0));
  std::fill(delta_wire_share_.begin(), delta_wire_share_.end(), Field(0));
  if (!input_proto_ || !mul_proto_ || !cmp_proto_) {
    throw std::runtime_error(
        "MaliciousAppEvaluator.onlineBatched requires offline() to initialize protocol state");
  }

  {
    auto auth_inputs = input_proto_->maliciousInputShareForTesting(inputs, offline_data.input_auth);
    for (const auto& [w, x] : auth_inputs.x_shares) {
      wire_share_[w] = x;
    }
    for (const auto& [w, dx] : auth_inputs.delta_x_shares) {
      delta_wire_share_[w] = dx;
    }
  }

  for (const auto& level : circ_.gates_by_level) {
    std::vector<const FIn2Gate*> mul_gates;
    std::vector<const FIn1Gate*> ltz_gates;
    std::vector<const FIn1Gate*> eqz_gates;

    for (const auto& gate : level) {
      switch (gate->type) {
        case GateType::kInp:
          break;
        case GateType::kAdd: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] + wire_share_[g->in2];
          delta_wire_share_[g->out] = delta_wire_share_[g->in1] + delta_wire_share_[g->in2];
          break;
        }
        case GateType::kSub: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] - wire_share_[g->in2];
          delta_wire_share_[g->out] = delta_wire_share_[g->in1] - delta_wire_share_[g->in2];
          break;
        }
        case GateType::kConstAdd: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] + ((id_ == 0) ? g->cval : Field(0));
          if (id_ < nP_) {
            delta_wire_share_[g->out] =
                delta_wire_share_[g->in] + offline_data.delta_share * g->cval;
          }
          break;
        }
        case GateType::kConstMul: {
          auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in] * g->cval;
          delta_wire_share_[g->out] = delta_wire_share_[g->in] * g->cval;
          break;
        }
        case GateType::kMul:
          mul_gates.push_back(static_cast<FIn2Gate*>(gate.get()));
          break;
        case GateType::kLtz:
          ltz_gates.push_back(static_cast<FIn1Gate*>(gate.get()));
          break;
        case GateType::kEqz:
          eqz_gates.push_back(static_cast<FIn1Gate*>(gate.get()));
          break;
        default:
          throw std::runtime_error("MaliciousAppEvaluator encountered unsupported gate type");
      }
    }

    if (!mul_gates.empty()) {
      std::vector<Field> x_shares;
      std::vector<Field> delta_x_shares;
      std::vector<Field> y_shares;
      std::vector<Field> delta_y_shares;
      std::vector<const MulOfflineData*> offline_vec;
      x_shares.reserve(mul_gates.size());
      delta_x_shares.reserve(mul_gates.size());
      y_shares.reserve(mul_gates.size());
      delta_y_shares.reserve(mul_gates.size());
      offline_vec.reserve(mul_gates.size());
      for (const auto* g : mul_gates) {
        auto it = offline_data.mul_gates.find(g->out);
        if (it == offline_data.mul_gates.end()) {
          throw std::runtime_error("Missing malicious mul offline data for application gate");
        }
        x_shares.push_back(wire_share_[g->in1]);
        delta_x_shares.push_back(delta_wire_share_[g->in1]);
        y_shares.push_back(wire_share_[g->in2]);
        delta_y_shares.push_back(delta_wire_share_[g->in2]);
        offline_vec.push_back(&it->second);
      }
      const auto mul_out = mul_proto_->mul_online_malicious_batch(
          x_shares, delta_x_shares, y_shares, delta_y_shares, offline_vec);
      for (size_t i = 0; i < mul_gates.size(); ++i) {
        wire_share_[mul_gates[i]->out] = mul_out[i].share;
        delta_wire_share_[mul_gates[i]->out] = mul_out[i].delta_share;
      }
    }

    if (!ltz_gates.empty()) {
      std::vector<Field> x_shares;
      std::vector<Field> delta_x_shares;
      std::vector<const CompareOfflineDataMalicious*> offline_vec;
      x_shares.reserve(ltz_gates.size());
      delta_x_shares.reserve(ltz_gates.size());
      offline_vec.reserve(ltz_gates.size());
      for (const auto* g : ltz_gates) {
        auto it = offline_data.compare_gates.find(g->out);
        if (it == offline_data.compare_gates.end()) {
          throw std::runtime_error("Missing malicious compare offline data for application gate");
        }
        x_shares.push_back(wire_share_[g->in]);
        delta_x_shares.push_back(delta_wire_share_[g->in]);
        offline_vec.push_back(&it->second);
      }
      std::vector<AuthCompareResult> cmp_out;
      try {
        cmp_out = cmp_proto_->compare_online_malicious_batch(x_shares, delta_x_shares, offline_vec);
      } catch (const std::exception& ex) {
        throw std::runtime_error("MaliciousAppEvaluator LTZ batch failed: " + std::string(ex.what()));
      }
      for (size_t i = 0; i < ltz_gates.size(); ++i) {
        const Field one_share = (id_ == 0) ? Field(1) : Field(0);
        wire_share_[ltz_gates[i]->out] = one_share - cmp_out[i].gtez_share;
        delta_wire_share_[ltz_gates[i]->out] =
            offline_vec[i]->delta_share - cmp_out[i].delta_gtez_share;
      }
    }

    if (!eqz_gates.empty()) {
      std::vector<Field> x_shares;
      std::vector<Field> delta_x_shares;
      std::vector<const EqzOfflineDataMalicious*> offline_vec;
      x_shares.reserve(eqz_gates.size());
      delta_x_shares.reserve(eqz_gates.size());
      offline_vec.reserve(eqz_gates.size());
      for (const auto* g : eqz_gates) {
        auto it = offline_data.eqz_gates.find(g->out);
        if (it == offline_data.eqz_gates.end()) {
          throw std::runtime_error("Missing malicious EQZ offline data for application gate");
        }
        x_shares.push_back(wire_share_[g->in]);
        delta_x_shares.push_back(delta_wire_share_[g->in]);
        offline_vec.push_back(&it->second);
      }
      std::vector<AuthEqzResult> eqz_out;
      try {
        eqz_out = cmp_proto_->eqz_online_malicious_batch(x_shares, delta_x_shares, offline_vec);
      } catch (const std::exception& ex) {
        throw std::runtime_error("MaliciousAppEvaluator EQZ batch failed: " + std::string(ex.what()));
      }
      for (size_t i = 0; i < eqz_gates.size(); ++i) {
        wire_share_[eqz_gates[i]->out] = eqz_out[i].eqz_share;
        delta_wire_share_[eqz_gates[i]->out] = eqz_out[i].delta_eqz_share;
      }
    }
  }

  std::vector<Field> outputs;
  outputs.reserve(circ_.outputs.size());
  for (auto wid : circ_.outputs) {
    outputs.push_back(wire_share_[wid]);
  }
  return outputs;
}

std::vector<Field> MaliciousAppEvaluator::deltaOutputs() const {
  std::vector<Field> outputs;
  outputs.reserve(circ_.outputs.size());
  for (auto wid : circ_.outputs) {
    outputs.push_back(delta_wire_share_[wid]);
  }
  return outputs;
}

}  // namespace asterisk2
