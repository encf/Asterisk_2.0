#include "protocol.h"

#include <random>
#include <stdexcept>

namespace asterisk2 {

namespace {
Field randomField(std::mt19937_64& rng) {
  return NTL::conv<Field>(NTL::to_ZZ(static_cast<unsigned long>(rng())));
}

std::mt19937_64 partyHelperRng(int seed, int party_id, size_t gate_idx) {
  return std::mt19937_64(static_cast<uint64_t>(seed) * 1000003ULL +
                         static_cast<uint64_t>(party_id) * 1315423911ULL +
                         gate_idx);
}

std::mt19937_64 helperTripleRng(int seed, size_t gate_idx) {
  return std::mt19937_64(static_cast<uint64_t>(seed) * 7919ULL + gate_idx);
}
}  // namespace

Protocol::Protocol(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                   LevelOrderedCircuit circ, int seed)
    : nP_(nP),
      id_(id),
      helper_id_(nP),
      seed_(seed),
      network_(std::move(network)),
      circ_(std::move(circ)),
      wire_share_(circ_.num_gates, Field(0)) {}

std::vector<TripleShare> Protocol::offline() {
  if (nP_ < 2) {
    throw std::runtime_error("Asterisk2.0 requires at least 2 computing parties");
  }

  std::vector<FIn2Gate> mul_gates;
  for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      if (gate->type == common::utils::GateType::kMul) {
        mul_gates.push_back(*std::dynamic_pointer_cast<FIn2Gate>(gate));
      }
    }
  }

  std::vector<TripleShare> triples(mul_gates.size());

  for (size_t g = 0; g < mul_gates.size(); ++g) {
    if (id_ <= nP_ - 2) {
      auto rng = partyHelperRng(seed_, id_, g);
      triples[g].a = randomField(rng);
      triples[g].b = randomField(rng);
      triples[g].c = randomField(rng);
    }
  }

  if (id_ == helper_id_) {
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      auto rg = helperTripleRng(seed_, g);
      Field a = randomField(rg);
      Field b = randomField(rg);
      Field c = a * b;

      Field sum_a = Field(0);
      Field sum_b = Field(0);
      Field sum_c = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto rng = partyHelperRng(seed_, i, g);
        auto ai = randomField(rng);
        auto bi = randomField(rng);
        auto ci = randomField(rng);
        sum_a += ai;
        sum_b += bi;
        sum_c += ci;
      }

      Field an = a - sum_a;
      Field bn = b - sum_b;
      Field cn = c - sum_c;
      Field pack[3] = {an, bn, cn};
      network_->send(nP_ - 1, pack, 3);
    }
    network_->flush();
    return triples;
  }

  if (id_ >= helper_id_) {
    return triples;
  }

  if (id_ == nP_ - 1) {
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      Field pack[3];
      network_->recv(helper_id_, pack, 3);
      triples[g].a = pack[0];
      triples[g].b = pack[1];
      triples[g].c = pack[2];
    }
  }

  return triples;
}

Field Protocol::openToComputingParties(const Field& share) {
  if (id_ >= helper_id_) {
    return Field(0);
  }

  for (int p = 0; p < helper_id_; ++p) {
    if (p != id_) {
      network_->send(p, &share, 1);
    }
  }
  network_->flush();

  Field sum = share;
  for (int p = 0; p < helper_id_; ++p) {
    if (p != id_) {
      Field tmp;
      network_->recv(p, &tmp, 1);
      sum += tmp;
    }
  }
  return sum;
}

Field Protocol::evalMulGate(const FIn2Gate& gate, const TripleShare& t) {
  Field x = wire_share_[gate.in1];
  Field y = wire_share_[gate.in2];

  Field d_share = x - t.a;
  Field e_share = y - t.b;

  Field d = openToComputingParties(d_share);
  Field e = openToComputingParties(e_share);

  Field out = e * t.a + d * t.b + t.c;
  if (id_ == 0) {
    out += d * e;
  }
  return out;
}

std::vector<Field> Protocol::online(
    const std::unordered_map<wire_t, Field>& inputs,
    const std::vector<TripleShare>& triples) {
  if (id_ >= helper_id_) {
    return {};
  }

  size_t mul_idx = 0;
  for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      switch (gate->type) {
        case common::utils::GateType::kInp: {
          auto it = inputs.find(gate->out);
          wire_share_[gate->out] = (it == inputs.end()) ? Field(0) : it->second;
          break;
        }
        case common::utils::GateType::kAdd: {
          auto g = std::dynamic_pointer_cast<FIn2Gate>(gate);
          wire_share_[g->out] = wire_share_[g->in1] + wire_share_[g->in2];
          break;
        }
        case common::utils::GateType::kSub: {
          auto g = std::dynamic_pointer_cast<FIn2Gate>(gate);
          wire_share_[g->out] = wire_share_[g->in1] - wire_share_[g->in2];
          break;
        }
        case common::utils::GateType::kMul: {
          auto g = std::dynamic_pointer_cast<FIn2Gate>(gate);
          if (mul_idx >= triples.size()) {
            throw std::runtime_error("Insufficient Beaver triples in online phase");
          }
          wire_share_[g->out] = evalMulGate(*g, triples[mul_idx]);
          ++mul_idx;
          break;
        }
        default:
          throw std::runtime_error("Asterisk2.0 benchmark currently supports Inp/Add/Sub/Mul only");
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

}  // namespace asterisk2
