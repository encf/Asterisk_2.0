#include "protocol.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <future>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <thread>

#include <emp-tool/emp-tool.h>

#include "mac_setup.h"

namespace asterisk2 {

namespace {
using emp::block;

constexpr uint64_t kPrime64Minus59 = 18446744073709551557ULL;

enum class PrgLabel : uint64_t {
  kMulShare = 0x4d554c5348415245ULL,
  kMulHelper = 0x4d554c48454c5046ULL,
  kMulMaliciousShare = 0x4d554c4d4c534852ULL,
  kMulMaliciousHelper = 0x4d554c4d4c484c50ULL,
  kMaliciousDeltaShare = 0x4d4143444c545348ULL,
  kMaliciousDeltaHelper = 0x4d4143444c54484cULL,
  kTruncShare = 0x5452554e43534852ULL,
  kTruncHelper = 0x5452554e43484c50ULL,
  kCmpMask = 0x434d504d41534b53ULL,
  kCmpShuffle = 0x434d505348554646ULL,
  kCmpBit = 0x434d504249545f5fULL,
  kCmpHelperShare = 0x434d504853484152ULL,
  kInputOwnerMask = 0x494e504f574e4d53ULL,
  kInputGlobalMask = 0x494e50474c4d4153ULL,
  kInputXRShare = 0x494e505852534852ULL,
  kInputDeltaXRShare = 0x494e504458525348ULL,
};

emp::PRG makePrg(int seed, int party_id, uint64_t idx, PrgLabel label) {
  // Shared-key derived deterministic CSPRNG stream (EMP PRG).
  const uint64_t lo = (static_cast<uint64_t>(static_cast<uint32_t>(seed)) << 32) ^
                      static_cast<uint32_t>(party_id);
  const uint64_t hi = idx ^ static_cast<uint64_t>(label);
  block key = emp::makeBlock(hi, lo);
  return emp::PRG(&key, 0);
}

emp::PRG makePrgFromPairwiseKey(const PairwiseKey& pairwise_key, uint64_t idx, PrgLabel label) {
  const uint64_t lo = pairwise_key.lo ^ idx;
  const uint64_t hi = pairwise_key.hi ^ static_cast<uint64_t>(label);
  block key = emp::makeBlock(hi, lo);
  return emp::PRG(&key, 0);
}

uint64_t prgUint64(emp::PRG& prg) {
  uint64_t v = 0;
  prg.random_data(&v, sizeof(v));
  return v;
}

Field prgField(emp::PRG& prg) {
  return NTL::conv<Field>(NTL::to_ZZ(prgUint64(prg) % kPrime64Minus59));
}

Field prgFieldBounded(emp::PRG& prg, uint64_t bound) {
  if (bound == 0) {
    return Field(0);
  }
  return NTL::conv<Field>(NTL::to_ZZ(prgUint64(prg) % bound));
}

Field prgNonZeroField(emp::PRG& prg) {
  Field f = Field(0);
  while (f == Field(0)) {
    f = prgField(prg);
  }
  return f;
}

bool prgBit(emp::PRG& prg) {
  return (prgUint64(prg) & 1ULL) == 1ULL;
}

uint64_t pow2Bound(size_t bits) {
  if (bits >= 64) {
    throw std::runtime_error("pow2Bound supports bit lengths < 64");
  }
  return (1ULL << bits);
}

std::vector<uint8_t> serializeFieldVector(const std::vector<Field>& data) {
  std::vector<uint8_t> out(data.size() * common::utils::FIELDSIZE);
  for (size_t i = 0; i < data.size(); ++i) {
    NTL::BytesFromZZ(out.data() + i * common::utils::FIELDSIZE,
                     NTL::conv<NTL::ZZ>(data[i]), common::utils::FIELDSIZE);
  }
  return out;
}

std::vector<Field> deserializeFieldVector(const std::vector<uint8_t>& in) {
  const size_t len = in.size() / common::utils::FIELDSIZE;
  std::vector<Field> out(len, Field(0));
  for (size_t i = 0; i < len; ++i) {
    out[i] = NTL::conv<Field>(NTL::ZZFromBytes(in.data() + i * common::utils::FIELDSIZE,
                                               common::utils::FIELDSIZE));
  }
  return out;
}

}  // namespace

Protocol::Protocol(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                   LevelOrderedCircuit circ, int seed, ProtocolConfig config)
    : nP_(nP),
      id_(id),
      helper_id_(nP),
      seed_(seed),
      key_manager_(nP, id, seed),
      config_(config),
      network_(std::move(network)),
      circ_(std::move(circ)),
      wire_share_(circ_.num_gates, Field(0)) {}

std::vector<int> Protocol::computingPeerIdsExcludingSelf() const {
  std::vector<int> peers;
  if (id_ >= helper_id_) {
    return peers;
  }
  for (int p = 0; p < helper_id_; ++p) {
    if (p != id_) {
      peers.push_back(p);
    }
  }
  return peers;
}

void Protocol::sendFieldVectorToPeers(const std::vector<int>& peers,
                                      const std::vector<Field>& data) const {
  if (peers.empty() || data.empty()) {
    return;
  }
  // Intentionally parallelized communication round.
  auto payload = serializeFieldVector(data);
  std::vector<std::thread> threads;
  threads.reserve(peers.size());
  for (int peer : peers) {
    threads.emplace_back([&, peer]() {
      auto* channel = network_->getSendChannel(peer);
      channel->send_data(payload.data(), payload.size());
      channel->flush();
    });
  }
  for (auto& th : threads) {
    th.join();
  }
}

std::vector<std::vector<Field>> Protocol::recvFieldVectorsFromPeers(
    const std::vector<int>& peers, size_t len) const {
  if (peers.empty() || len == 0) {
    return {};
  }
  const size_t bytes = len * common::utils::FIELDSIZE;
  std::vector<std::vector<uint8_t>> recv_serialized(peers.size(),
                                                    std::vector<uint8_t>(bytes));
  // Intentionally parallelized communication round.
  std::vector<std::thread> threads;
  threads.reserve(peers.size());
  for (size_t i = 0; i < peers.size(); ++i) {
    threads.emplace_back([&, i]() {
      auto* channel = network_->getRecvChannel(peers[i]);
      channel->recv_data(recv_serialized[i].data(), recv_serialized[i].size());
    });
  }
  for (auto& th : threads) {
    th.join();
  }

  std::vector<std::vector<Field>> out;
  out.reserve(peers.size());
  for (const auto& buf : recv_serialized) {
    out.push_back(deserializeFieldVector(buf));
  }
  return out;
}

MulOfflineData Protocol::mul_offline() {
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

  if (config_.security_model == SecurityModel::kMalicious) {
    return mul_offline_malicious(mul_gates);
  }
  return mul_offline_semi_honest(mul_gates);
}

MulOfflineData Protocol::mul_offline_semi_honest(const std::vector<FIn2Gate>& mul_gates) {
  MulOfflineData out;
  out.triples.resize(mul_gates.size());
  if (id_ <= nP_ - 2) {
    const auto pairwise_key = key_manager_.keyWithHelper();
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      auto prg = makePrgFromPairwiseKey(pairwise_key, g, PrgLabel::kMulShare);
      out.triples[g].a = prgField(prg);
      out.triples[g].b = prgField(prg);
      out.triples[g].c = prgField(prg);
    }
    out.ready = true;
    return out;
  }

  if (id_ == helper_id_) {
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      auto helper_prg = makePrg(seed_, helper_id_, g, PrgLabel::kMulHelper);
      Field a = prgField(helper_prg);
      Field b = prgField(helper_prg);
      Field c = a * b;

      Field sum_a = Field(0);
      Field sum_b = Field(0);
      Field sum_c = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto pprg = makePrgFromPairwiseKey(key_manager_.keyForParty(i), g, PrgLabel::kMulShare);
        sum_a += prgField(pprg);
        sum_b += prgField(pprg);
        sum_c += prgField(pprg);
      }

      std::vector<Field> pack = {a - sum_a, b - sum_b, c - sum_c};
      maybeSimulateStep(pack.size() * common::utils::FIELDSIZE);
      network_->send(nP_ - 1, pack.data(), pack.size() * common::utils::FIELDSIZE);
    }

    network_->flush();
    out.ready = true;
    return out;
  }

  if (id_ == nP_ - 1) {
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      Field pack[3];
      network_->recv(helper_id_, pack, 3 * common::utils::FIELDSIZE);
      out.triples[g] = {pack[0], pack[1], pack[2]};
    }
  }
  out.ready = true;
  return out;
}

MulOfflineData Protocol::mul_offline_malicious(const std::vector<FIn2Gate>& mul_gates) {
  MulOfflineData out;
  out.triples.resize(mul_gates.size());
  out.auth_tuples.resize(mul_gates.size());
  if (id_ <= nP_ - 2) {
    const auto pairwise = key_manager_.keyWithHelper();
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      auto prg = makePrgFromPairwiseKey(pairwise, g, PrgLabel::kMulMaliciousShare);
      out.triples[g].a = prgField(prg);
      out.triples[g].b = prgField(prg);
      out.triples[g].c = prgField(prg);
      out.auth_tuples[g].a_prime = prgField(prg);
      out.auth_tuples[g].b_prime = prgField(prg);
      out.auth_tuples[g].c_prime = prgField(prg);
      out.auth_tuples[g].a_prime_b_prime = prgField(prg);
      out.auth_tuples[g].a_prime_c_prime = prgField(prg);
      out.auth_tuples[g].b_prime_c_prime = prgField(prg);
      out.auth_tuples[g].a_prime_b_prime_c_prime = prgField(prg);
    }
  } else if (id_ == helper_id_) {
    std::vector<Field> batch_pack(10 * mul_gates.size(), Field(0));
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      auto helper_prg = makePrg(seed_, helper_id_, g, PrgLabel::kMulMaliciousHelper);
      const Field a = prgField(helper_prg);
      const Field b = prgField(helper_prg);
      const Field a_prime = prgField(helper_prg);
      const Field b_prime = prgField(helper_prg);
      const Field c_prime = prgField(helper_prg);
      const Field ab = a * b;
      const Field a_prime_b_prime = a_prime * b_prime;
      const Field a_prime_c_prime = a_prime * c_prime;
      const Field b_prime_c_prime = b_prime * c_prime;
      const Field a_prime_b_prime_c_prime = a_prime * b_prime * c_prime;

      Field sum_a = Field(0);
      Field sum_b = Field(0);
      Field sum_ab = Field(0);
      Field sum_a_prime = Field(0);
      Field sum_b_prime = Field(0);
      Field sum_c_prime = Field(0);
      Field sum_a_prime_b_prime = Field(0);
      Field sum_a_prime_c_prime = Field(0);
      Field sum_b_prime_c_prime = Field(0);
      Field sum_a_prime_b_prime_c_prime = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto pprg = makePrgFromPairwiseKey(key_manager_.keyForParty(i), g,
                                           PrgLabel::kMulMaliciousShare);
        sum_a += prgField(pprg);
        sum_b += prgField(pprg);
        sum_ab += prgField(pprg);
        sum_a_prime += prgField(pprg);
        sum_b_prime += prgField(pprg);
        sum_c_prime += prgField(pprg);
        sum_a_prime_b_prime += prgField(pprg);
        sum_a_prime_c_prime += prgField(pprg);
        sum_b_prime_c_prime += prgField(pprg);
        sum_a_prime_b_prime_c_prime += prgField(pprg);
      }

      batch_pack[10 * g + 0] = a - sum_a;
      batch_pack[10 * g + 1] = b - sum_b;
      batch_pack[10 * g + 2] = ab - sum_ab;
      batch_pack[10 * g + 3] = a_prime - sum_a_prime;
      batch_pack[10 * g + 4] = b_prime - sum_b_prime;
      batch_pack[10 * g + 5] = c_prime - sum_c_prime;
      batch_pack[10 * g + 6] = a_prime_b_prime - sum_a_prime_b_prime;
      batch_pack[10 * g + 7] = a_prime_c_prime - sum_a_prime_c_prime;
      batch_pack[10 * g + 8] = b_prime_c_prime - sum_b_prime_c_prime;
      batch_pack[10 * g + 9] = a_prime_b_prime_c_prime - sum_a_prime_b_prime_c_prime;
    }
    maybeSimulateStep(batch_pack.size() * common::utils::FIELDSIZE);
    network_->send(nP_ - 1, batch_pack.data(), batch_pack.size() * common::utils::FIELDSIZE);
    network_->flush();
  } else if (id_ == nP_ - 1) {
    std::vector<Field> batch_pack(10 * mul_gates.size(), Field(0));
    network_->recv(helper_id_, batch_pack.data(),
                   batch_pack.size() * common::utils::FIELDSIZE);
    for (size_t g = 0; g < mul_gates.size(); ++g) {
      out.triples[g] = {batch_pack[10 * g + 0], batch_pack[10 * g + 1], batch_pack[10 * g + 2]};
      out.auth_tuples[g] = {batch_pack[10 * g + 3], batch_pack[10 * g + 4],
                            batch_pack[10 * g + 5], batch_pack[10 * g + 6],
                            batch_pack[10 * g + 7], batch_pack[10 * g + 8],
                            batch_pack[10 * g + 9]};
    }
  }

  const auto mac_setup = runMacSetupDH(nP_, id_, network_, key_manager_, seed_);
  if (id_ < helper_id_) {
    out.delta_share = mac_setup.party.delta_share;
    out.delta_inv_share = mac_setup.party.delta_inv_share;
  } else if (id_ == helper_id_) {
    out.helper_delta = mac_setup.helper.delta;
    out.helper_delta_inv = mac_setup.helper.delta_inv;
  }
  out.ready = true;
  return out;
}

std::vector<Field> Protocol::mul_online(const std::unordered_map<wire_t, Field>& inputs,
                                        const MulOfflineData& offline_data) {
  if (config_.security_model == SecurityModel::kMalicious) {
    return mul_online_malicious(inputs, offline_data);
  }
  return mul_online_semi_honest(inputs, offline_data);
}

std::vector<Field> Protocol::mul_online_semi_honest(
    const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data) {
  if (!offline_data.ready) {
    throw std::runtime_error("mul_online requires ready MulOfflineData from mul_offline");
  }
  if (id_ >= helper_id_) {
    return {};
  }

  size_t mul_idx = 0;
  for (const auto& level : circ_.gates_by_level) {
    std::vector<const FIn2Gate*> mul_gates;
    mul_gates.reserve(level.size());

    for (const auto& gate : level) {
      switch (gate->type) {
        case common::utils::GateType::kInp: {
          auto it = inputs.find(gate->out);
          wire_share_[gate->out] = (it == inputs.end()) ? Field(0) : it->second;
          break;
        }
        case common::utils::GateType::kAdd: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] + wire_share_[g->in2];
          break;
        }
        case common::utils::GateType::kSub: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] - wire_share_[g->in2];
          break;
        }
        case common::utils::GateType::kMul: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          mul_gates.push_back(g);
          break;
        }
        default:
          throw std::runtime_error("Asterisk2.0 benchmark currently supports Inp/Add/Sub/Mul only");
      }
    }

    if (!mul_gates.empty()) {
      std::vector<OpenPair> local_pairs(mul_gates.size());
      for (size_t i = 0; i < mul_gates.size(); ++i) {
        if (mul_idx + i >= offline_data.triples.size()) {
          throw std::runtime_error("Insufficient Beaver triples in mul_online phase");
        }
        const auto* g = mul_gates[i];
        const auto& t = offline_data.triples[mul_idx + i];
        local_pairs[i].d = wire_share_[g->in1] - t.a;
        local_pairs[i].e = wire_share_[g->in2] - t.b;
      }

      auto opened = openPairsToComputingParties(local_pairs);
      for (size_t i = 0; i < mul_gates.size(); ++i) {
        const auto* g = mul_gates[i];
        const auto& t = offline_data.triples[mul_idx + i];
        Field out = opened[i].e * t.a + opened[i].d * t.b + t.c;
        if (id_ == 0) {
          out += opened[i].d * opened[i].e;
        }
        wire_share_[g->out] = out;
      }
      mul_idx += mul_gates.size();
    }
  }

  std::vector<Field> outputs;
  outputs.reserve(circ_.outputs.size());
  for (auto wid : circ_.outputs) {
    outputs.push_back(wire_share_[wid]);
  }
  return outputs;
}

std::vector<Field> Protocol::mul_online_malicious(
    const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data) {
  verifyMaliciousKeyMaterial(offline_data);
  const auto malicious_input_shares = buildMaliciousInputShares(inputs, offline_data);
  if (id_ >= helper_id_) {
    return {};
  }

  std::unordered_map<wire_t, Field> delta_wire_share = malicious_input_shares.delta_x_shares;
  size_t mul_idx = 0;
  for (const auto& level : circ_.gates_by_level) {
    std::vector<const FIn2Gate*> mul_gates;
    mul_gates.reserve(level.size());

    for (const auto& gate : level) {
      switch (gate->type) {
        case common::utils::GateType::kInp: {
          const auto xit = malicious_input_shares.x_shares.find(gate->out);
          wire_share_[gate->out] =
              (xit == malicious_input_shares.x_shares.end()) ? Field(0) : xit->second;
          const auto dit = malicious_input_shares.delta_x_shares.find(gate->out);
          delta_wire_share[gate->out] =
              (dit == malicious_input_shares.delta_x_shares.end()) ? Field(0) : dit->second;
          break;
        }
        case common::utils::GateType::kAdd: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] + wire_share_[g->in2];
          delta_wire_share[g->out] = delta_wire_share[g->in1] + delta_wire_share[g->in2];
          break;
        }
        case common::utils::GateType::kSub: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          wire_share_[g->out] = wire_share_[g->in1] - wire_share_[g->in2];
          delta_wire_share[g->out] = delta_wire_share[g->in1] - delta_wire_share[g->in2];
          break;
        }
        case common::utils::GateType::kMul: {
          auto* g = static_cast<FIn2Gate*>(gate.get());
          mul_gates.push_back(g);
          break;
        }
        default:
          throw std::runtime_error("Asterisk2.0 benchmark currently supports Inp/Add/Sub/Mul only");
      }
    }

    for (size_t i = 0; i < mul_gates.size(); ++i) {
      if (mul_idx + i >= offline_data.triples.size() ||
          mul_idx + i >= offline_data.auth_tuples.size()) {
        throw std::runtime_error("Insufficient malicious offline tuples in mul_online phase");
      }
      const auto* g = mul_gates[i];
      const auto& t = offline_data.triples[mul_idx + i];
      const auto& auth = offline_data.auth_tuples[mul_idx + i];

      const Field d_share = wire_share_[g->in1] - t.a;
      const Field e_share = wire_share_[g->in2] - t.b;
      const Field d_delta_share = delta_wire_share[g->in1] - auth.a_prime;
      const Field e_delta_share = delta_wire_share[g->in2] - auth.b_prime;
      const Field f_share = d_delta_share * e_delta_share - auth.c_prime;

      const Field d = openToComputingParties(d_share);
      const Field e = openToComputingParties(e_share);
      const Field d_delta = openToComputingParties(d_delta_share);
      const Field e_delta = openToComputingParties(e_delta_share);
      const Field f = openToComputingParties(f_share);

      Field xy_share = e * t.a + d * t.b + t.c;
      if (id_ == 0) {
        xy_share += d * e;
      }

      Field delta_xy_share = e * auth.a_prime + d * auth.b_prime + auth.c_prime;
      if (id_ == 0) {
        delta_xy_share += d * e_delta;
      }
      delta_xy_share += auth.a_prime_c_prime * e_delta + auth.b_prime_c_prime * d_delta +
                        auth.a_prime_b_prime * f + auth.a_prime_b_prime_c_prime;

      wire_share_[g->out] = xy_share;
      delta_wire_share[g->out] = delta_xy_share;
    }
    mul_idx += mul_gates.size();
  }

  std::vector<Field> outputs;
  outputs.reserve(circ_.outputs.size());
  for (auto wid : circ_.outputs) {
    outputs.push_back(wire_share_[wid]);
  }
  return outputs;
}

MaliciousInputShareData Protocol::buildMaliciousInputShares(
    const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data) {
  MaliciousInputShareData out;
  if (!offline_data.ready) {
    throw std::runtime_error("malicious input sharing requires ready MulOfflineData");
  }

  constexpr int kDefaultInputOwner = 0;
  if (nP_ < 1) {
    throw std::runtime_error("malicious input sharing requires at least one computing party");
  }

  Field helper_delta = Field(0);
  if (id_ == helper_id_) {
    helper_delta = offline_data.helper_delta;
    if (helper_delta == Field(0)) {
      auto helper_prg = makePrg(seed_, helper_id_, 0, PrgLabel::kMaliciousDeltaHelper);
      helper_delta = prgNonZeroField(helper_prg);
    }
  }
  size_t input_idx = 0;
  for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      if (gate->type != common::utils::GateType::kInp) {
        continue;
      }
      const wire_t w = gate->out;

      if (id_ == helper_id_) {
        Field x_prime = Field(0);
        network_->recv(kDefaultInputOwner, &x_prime, common::utils::FIELDSIZE);

        const auto owner_pairwise = key_manager_.keyForParty(kDefaultInputOwner);
        auto t_prg =
            makePrgFromPairwiseKey(owner_pairwise, input_idx, PrgLabel::kInputOwnerMask);
        const Field t = prgField(t_prg);
        const Field x_plus_r = x_prime - t;
        const Field delta_x_plus_r = helper_delta * x_plus_r;

        Field sum_x_plus_r = Field(0);
        Field sum_delta_x_plus_r = Field(0);
        for (int i = 0; i <= nP_ - 2; ++i) {
          const auto pi_key = key_manager_.keyForParty(i);
          auto x_prg = makePrgFromPairwiseKey(pi_key, input_idx, PrgLabel::kInputXRShare);
          auto dx_prg =
              makePrgFromPairwiseKey(pi_key, input_idx, PrgLabel::kInputDeltaXRShare);
          sum_x_plus_r += prgField(x_prg);
          sum_delta_x_plus_r += prgField(dx_prg);
        }

        Field pack[2] = {x_plus_r - sum_x_plus_r, delta_x_plus_r - sum_delta_x_plus_r};
        maybeSimulateStep(2 * common::utils::FIELDSIZE);
        network_->send(nP_ - 1, pack, 2 * common::utils::FIELDSIZE);
        network_->flush();
      } else {
        const auto kp = key_manager_.computingPartiesKey();
        auto r_prg = makePrgFromPairwiseKey(kp, input_idx, PrgLabel::kInputGlobalMask);
        const Field r = prgField(r_prg);

        Field x_plus_r_share = Field(0);
        Field delta_x_plus_r_share = Field(0);
        if (id_ <= nP_ - 2) {
          const auto pairwise = key_manager_.keyWithHelper();
          auto x_prg =
              makePrgFromPairwiseKey(pairwise, input_idx, PrgLabel::kInputXRShare);
          auto dx_prg =
              makePrgFromPairwiseKey(pairwise, input_idx, PrgLabel::kInputDeltaXRShare);
          x_plus_r_share = prgField(x_prg);
          delta_x_plus_r_share = prgField(dx_prg);
        } else {
          Field pack[2] = {Field(0), Field(0)};
          network_->recv(helper_id_, pack, 2 * common::utils::FIELDSIZE);
          x_plus_r_share = pack[0];
          delta_x_plus_r_share = pack[1];
        }

        if (id_ == kDefaultInputOwner) {
          const auto owner_pairwise = key_manager_.keyWithHelper();
          auto t_prg =
              makePrgFromPairwiseKey(owner_pairwise, input_idx, PrgLabel::kInputOwnerMask);
          const Field t = prgField(t_prg);
          const auto it = inputs.find(w);
          const Field x = (it == inputs.end()) ? Field(0) : it->second;
          const Field x_prime = x + r + t;
          maybeSimulateStep(common::utils::FIELDSIZE);
          network_->send(helper_id_, &x_prime, common::utils::FIELDSIZE);
          network_->flush();
        }

        const Field x_share = x_plus_r_share - ((id_ == kDefaultInputOwner) ? r : Field(0));
        const Field delta_x_share = delta_x_plus_r_share - offline_data.delta_share * r;
        out.x_shares[w] = x_share;
        out.delta_x_shares[w] = delta_x_share;
      }

      ++input_idx;
    }
  }

  return out;
}

MaliciousInputShareData Protocol::maliciousInputShareForTesting(
    const std::unordered_map<wire_t, Field>& inputs, const MulOfflineData& offline_data) {
  if (config_.security_model != SecurityModel::kMalicious) {
    throw std::runtime_error("maliciousInputShareForTesting requires malicious security model");
  }
  verifyMaliciousKeyMaterial(offline_data);
  return buildMaliciousInputShares(inputs, offline_data);
}

void Protocol::verifyMaliciousKeyMaterial(const MulOfflineData& offline_data) const {
  if (!offline_data.ready) {
    throw std::runtime_error("malicious verify requires ready MulOfflineData");
  }

  if (id_ >= helper_id_) {
    return;
  }

  const Field delta = openToComputingParties(offline_data.delta_share);
  const Field delta_inv = openToComputingParties(offline_data.delta_inv_share);
  if (delta == Field(0) || delta * delta_inv != Field(1)) {
    throw std::runtime_error("malicious key-material consistency check failed");
  }
}

TruncOfflineData Protocol::trunc_offline(size_t batch_size, size_t ell_x, size_t m, size_t s) {
  if (id_ > helper_id_) {
    return {};
  }
  if (m == 0 || m > ell_x) {
    throw std::runtime_error("trunc_offline requires 0 < m <= ell_x");
  }
  if (ell_x + s + 1 >= 64) {
    throw std::runtime_error("trunc_offline requires ell_x + s + 1 < 64");
  }

  TruncOfflineData off;
  off.ell_x = ell_x;
  off.m = m;
  off.s = s;
  off.r_share.assign(batch_size, Field(0));
  off.r0_share.assign(batch_size, Field(0));

  const uint64_t bound_r = pow2Bound(ell_x - m + s);
  const uint64_t bound_r0 = pow2Bound(m);

  if (id_ == helper_id_) {
    for (size_t idx = 0; idx < batch_size; ++idx) {
      auto helper_prg = makePrg(seed_, helper_id_, idx, PrgLabel::kTruncHelper);
      Field r = prgFieldBounded(helper_prg, bound_r);
      Field r0 = prgFieldBounded(helper_prg, bound_r0);

      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto pprg = makePrgFromPairwiseKey(key_manager_.keyForParty(i), idx,
                                           PrgLabel::kTruncShare);
        sum_r += prgFieldBounded(pprg, bound_r);
        sum_r0 += prgFieldBounded(pprg, bound_r0);
      }

      Field pack[2] = {r - sum_r, r0 - sum_r0};
      maybeSimulateStep(2 * common::utils::FIELDSIZE);
      network_->send(nP_ - 1, pack, 2 * common::utils::FIELDSIZE);
    }
    network_->flush();
    off.ready = true;
    return off;
  }

  if (id_ <= nP_ - 2) {
    const auto pairwise_key = key_manager_.keyWithHelper();
    for (size_t idx = 0; idx < batch_size; ++idx) {
      auto pprg = makePrgFromPairwiseKey(pairwise_key, idx, PrgLabel::kTruncShare);
      off.r_share[idx] = prgFieldBounded(pprg, bound_r);
      off.r0_share[idx] = prgFieldBounded(pprg, bound_r0);
    }
  } else if (id_ == nP_ - 1) {
    for (size_t idx = 0; idx < batch_size; ++idx) {
      Field pack[2];
      network_->recv(helper_id_, pack, 2 * common::utils::FIELDSIZE);
      off.r_share[idx] = pack[0];
      off.r0_share[idx] = pack[1];
    }
  }

  off.ready = true;
  return off;
}

std::vector<Field> Protocol::trunc_online(const std::vector<Field>& x_shares,
                                          const TruncOfflineData& offline_data) {
  if (id_ > helper_id_) {
    return {};
  }
  if (!offline_data.ready) {
    throw std::runtime_error("trunc_online requires ready TruncOfflineData from trunc_offline");
  }
  if (offline_data.r_share.size() != x_shares.size() ||
      offline_data.r0_share.size() != x_shares.size()) {
    throw std::runtime_error("trunc_online offline mask vector sizes must match input batch size");
  }

  const uint64_t two_pow_m = pow2Bound(offline_data.m);
  const uint64_t two_pow_lx_minus_1 = pow2Bound(offline_data.ell_x - 1);
  const Field lambda_m = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_m)));

  std::vector<Field> out(x_shares.size(), Field(0));
  for (size_t idx = 0; idx < x_shares.size(); ++idx) {
    Field z_i = x_shares[idx] + ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1))
                                            : Field(0));
    Field c_i = z_i + NTL::conv<Field>(NTL::to_ZZ(two_pow_m)) * offline_data.r_share[idx] +
                offline_data.r0_share[idx];
    Field c = openToComputingParties(c_i);
    uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c));
    uint64_t c0 = c_u64 & (two_pow_m - 1);
    Field d_i = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) -
                offline_data.r0_share[idx];
    out[idx] = lambda_m * (x_shares[idx] - d_i);
  }
  return out;
}

CompareOfflineData Protocol::compare_offline(size_t lx, size_t s, bool force_t,
                                             bool forced_t_value) {
  if (lx == 0) {
    throw std::runtime_error("compare_offline requires lx > 0");
  }
  if (lx + s + 1 >= 64) {
    throw std::runtime_error("compare_offline requires lx + s + 1 < 64");
  }

  CompareOfflineData out;
  out.trunc_data.lx = lx;
  out.trunc_data.s = s;
  out.trunc_data.r_share.assign(lx, Field(0));
  out.trunc_data.r0_share.assign(lx, Field(0));

  if (id_ == helper_id_) {
    std::vector<Field> pack(2 * lx, Field(0));
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto helper_prg = makePrg(seed_, helper_id_, j, PrgLabel::kTruncHelper);
      Field r = prgFieldBounded(helper_prg, bound_r);
      Field r0 = prgFieldBounded(helper_prg, bound_r0);
      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto pprg = makePrgFromPairwiseKey(key_manager_.keyForParty(i), j,
                                           PrgLabel::kTruncShare);
        sum_r += prgFieldBounded(pprg, bound_r);
        sum_r0 += prgFieldBounded(pprg, bound_r0);
      }
      pack[2 * (j - 1)] = r - sum_r;
      pack[2 * (j - 1) + 1] = r0 - sum_r0;
    }
    maybeSimulateStep(pack.size() * common::utils::FIELDSIZE);
    network_->send(nP_ - 1, pack.data(), pack.size() * common::utils::FIELDSIZE);
    network_->flush();
  } else if (id_ <= nP_ - 2) {
    const auto pairwise_key = key_manager_.keyWithHelper();
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto pprg = makePrgFromPairwiseKey(pairwise_key, j, PrgLabel::kTruncShare);
      out.trunc_data.r_share[j - 1] = prgFieldBounded(pprg, bound_r);
      out.trunc_data.r0_share[j - 1] = prgFieldBounded(pprg, bound_r0);
    }
  } else if (id_ == nP_ - 1) {
    std::vector<Field> pack(2 * lx, Field(0));
    network_->recv(helper_id_, pack.data(), pack.size() * common::utils::FIELDSIZE);
    for (size_t j = 0; j < lx; ++j) {
      out.trunc_data.r_share[j] = pack[2 * j];
      out.trunc_data.r0_share[j] = pack[2 * j + 1];
    }
  }

  out.trunc_data.ready = true;

  out.cmp_data.rho.assign(lx + 2, Field(0));
  out.cmp_data.permutation.resize(lx + 2);
  std::iota(out.cmp_data.permutation.begin(), out.cmp_data.permutation.end(), 0);
  out.cmp_data.t = false;

  // K_P: key shared among computing parties only, used to derive shared compare
  // randomness in compare_offline.
  if (id_ < helper_id_) {
    const auto kp = key_manager_.computingPartiesKey();
    for (size_t i = 0; i < out.cmp_data.rho.size(); ++i) {
      auto pprg = makePrgFromPairwiseKey(kp, i + 1, PrgLabel::kCmpMask);
      out.cmp_data.rho[i] = prgNonZeroField(pprg);
    }

    auto shuffle_prg = makePrgFromPairwiseKey(kp, lx, PrgLabel::kCmpShuffle);
    for (size_t i = out.cmp_data.permutation.size(); i > 1; --i) {
      size_t j = static_cast<size_t>(prgUint64(shuffle_prg) % i);
      std::swap(out.cmp_data.permutation[i - 1], out.cmp_data.permutation[j]);
    }

    if (force_t) {
      out.cmp_data.t = forced_t_value;
    } else {
      auto t_prg = makePrgFromPairwiseKey(kp, lx + 1, PrgLabel::kCmpBit);
      out.cmp_data.t = prgBit(t_prg);
    }
  }

  out.cmp_data.ready = true;
  out.ready = true;
  return out;
}

Field Protocol::compare_online(const Field& x_share, const CompareOfflineData& offline_data,
                               BGTEZStats* stats) {
  if (!offline_data.ready || !offline_data.trunc_data.ready || !offline_data.cmp_data.ready) {
    throw std::runtime_error("compare_online requires ready CompareOfflineData from compare_offline");
  }
  const size_t lx = offline_data.trunc_data.lx;
  const size_t s = offline_data.trunc_data.s;
  if (lx == 0 || lx + s + 1 >= 64) {
    throw std::runtime_error("compare_online got invalid offline truncation parameters");
  }

  if (id_ > helper_id_) {
    return Field(0);
  }

  if (id_ == helper_id_) {
    const size_t helper_payload_len = lx + 3;  // (v* and v_j) plus hat_x.
    std::vector<int> peers;
    peers.reserve(static_cast<size_t>(helper_id_));
    for (int p = 0; p < helper_id_; ++p) {
      peers.push_back(p);
    }
    // Round 2 receive (parallelized).
    const size_t bytes = helper_payload_len * common::utils::FIELDSIZE;
    std::vector<std::vector<uint8_t>> recv_payloads(
        peers.size(), std::vector<uint8_t>(bytes, 0));
    std::vector<std::thread> recv_threads;
    recv_threads.reserve(peers.size());
    for (size_t i = 0; i < peers.size(); ++i) {
      recv_threads.emplace_back([&, i]() {
        auto* channel = network_->getRecvChannel(peers[i]);
        channel->recv_data(recv_payloads[i].data(), bytes);
      });
    }
    for (auto& th : recv_threads) {
      th.join();
    }
    std::vector<Field> sum(helper_payload_len, Field(0));
    for (const auto& buf : recv_payloads) {
      auto vals = deserializeFieldVector(buf);
      for (size_t i = 0; i < vals.size(); ++i) {
        sum[i] += vals[i];
      }
    }

    bool any_zero = false;
    for (const auto& val : sum) {
      if (val == Field(0)) {
        any_zero = true;
        break;
      }
    }
    const uint64_t opened_raw = NTL::conv<uint64_t>(NTL::rep(sum.back()));
    int64_t opened_x = static_cast<int64_t>(opened_raw);
    if (opened_raw > (kPrime64Minus59 / 2ULL)) {
      opened_x = static_cast<int64_t>(opened_raw - kPrime64Minus59);
    }
    Field bit = (opened_x >= 0 || any_zero) ? Field(1) : Field(0);

    std::vector<Field> back(helper_id_, Field(0));
    Field partial = Field(0);
    for (int p = 0; p <= helper_id_ - 2; ++p) {
      auto prg = makePrg(seed_, helper_id_, static_cast<uint64_t>(p), PrgLabel::kCmpHelperShare);
      back[p] = prgField(prg);
      partial += back[p];
    }
    back[helper_id_ - 1] = bit - partial;

    // Round 3 send (parallelized).
    std::vector<std::thread> send_threads;
    send_threads.reserve(peers.size());
    for (int peer : peers) {
      send_threads.emplace_back([&, peer]() {
        auto* channel = network_->getSendChannel(peer);
        std::vector<uint8_t> payload(common::utils::FIELDSIZE);
        NTL::BytesFromZZ(payload.data(), NTL::conv<NTL::ZZ>(back[peer]), common::utils::FIELDSIZE);
        channel->send_data(payload.data(), payload.size());
        channel->flush();
      });
    }
    for (auto& th : send_threads) {
      th.join();
    }
    return Field(0);
  }

  const bool t = offline_data.cmp_data.t;
  Field hat_x = t ? -x_share : x_share;
  Field u_star = (id_ == 0) ? (t ? Field(-1) : Field(1)) : Field(0);
  Field u0 = hat_x;

  // Round 1 (batched): one opening for all truncation levels.
  std::vector<Field> c_local(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
    Field z = hat_x + ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
    c_local[j - 1] = z + NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) *
                             offline_data.trunc_data.r_share[j - 1] +
                     offline_data.trunc_data.r0_share[j - 1];
  }
  auto c_open = openVectorToComputingParties(c_local);
  if (stats != nullptr) {
    stats->batched_open_calls += 1;
  }
  if (c_open.size() != lx) {
    throw std::runtime_error("compare_online batched opening size mismatch");
  }

  std::vector<Field> u_trunc(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c_open[j - 1]));
    const uint64_t c0 = c_u64 & (two_pow_j - 1);
    Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) -
              offline_data.trunc_data.r0_share[j - 1];
    const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
    u_trunc[j - 1] = inv2pow * (hat_x - d);
  }

  std::vector<Field> u_all(lx + 1, Field(0));
  if (id_ < helper_id_) {
    u_all[0] = u0;
    for (size_t j = 1; j <= lx; ++j) {
      u_all[j] = u_trunc[j - 1];
    }
  }
  Field one_share = (id_ == 0) ? Field(1) : Field(0);

  Field v_star = u_star + Field(3) * u0 - one_share;
  std::vector<Field> v(lx + 1, Field(0));
  for (size_t j = 0; j <= lx; ++j) {
    Field sum = Field(0);
    for (size_t k = j; k <= lx; ++k) {
      sum += u_all[k];
    }
    v[j] = sum - one_share;
  }

  if (offline_data.cmp_data.rho.size() != lx + 2 ||
      offline_data.cmp_data.permutation.size() != lx + 2) {
    throw std::runtime_error("compare_online comparison mask/permutation size mismatch");
  }

  std::vector<Field> candidates(lx + 2, Field(0));
  candidates[0] = offline_data.cmp_data.rho[0] * v_star;
  for (size_t j = 0; j <= lx; ++j) {
    candidates[j + 1] = offline_data.cmp_data.rho[j + 1] * v[j];
  }

  std::vector<Field> shuffled(candidates.size(), Field(0));
  for (size_t i = 0; i < candidates.size(); ++i) {
    shuffled[i] = candidates[offline_data.cmp_data.permutation[i]];
  }
  std::vector<Field> helper_payload = shuffled;
  helper_payload.push_back(hat_x);

  // Round 2: computing parties send shuffled candidate shares to helper.
  if (id_ < helper_id_) {
    const auto payload = serializeFieldVector(helper_payload);
    maybeSimulateStep(payload.size());
    auto* channel = network_->getSendChannel(helper_id_);
    channel->send_data(payload.data(), payload.size());
    channel->flush();
  }

  // Round 3: helper sends back secret shares of comparison bit.
  Field bit_share = Field(0);
  std::vector<uint8_t> recv_payload(common::utils::FIELDSIZE);
  auto* recv_channel = network_->getRecvChannel(helper_id_);
  recv_channel->recv_data(recv_payload.data(), recv_payload.size());
  bit_share = NTL::conv<Field>(
      NTL::ZZFromBytes(recv_payload.data(), common::utils::FIELDSIZE));
  Field t_share = (id_ == 0 && t) ? Field(1) : Field(0);
  return t_share + bit_share - Field(2) * (t ? bit_share : Field(0));
}

std::vector<TripleShare> Protocol::offline() {
  return mul_offline().triples;
}

std::vector<Field> Protocol::online(const std::unordered_map<wire_t, Field>& inputs,
                                    const std::vector<TripleShare>& triples) {
  MulOfflineData off;
  off.triples = triples;
  off.ready = true;
  return mul_online(inputs, off);
}

std::vector<Field> Protocol::probabilisticTruncate(const std::vector<Field>& x_shares, size_t ell_x,
                                                   size_t m, size_t s) {
  auto off = trunc_offline(x_shares.size(), ell_x, m, s);
  return trunc_online(x_shares, off);
}

std::vector<Protocol::OpenPair> Protocol::openPairsToComputingParties(
    const std::vector<OpenPair>& local_pairs) const {
  if (id_ >= helper_id_) {
    return {};
  }

  std::vector<Field> send_buf(local_pairs.size() * 2);
  for (size_t i = 0; i < local_pairs.size(); ++i) {
    send_buf[2 * i] = local_pairs[i].d;
    send_buf[2 * i + 1] = local_pairs[i].e;
  }

  const auto peers = computingPeerIdsExcludingSelf();
  // Full-duplex model: peer send/recv overlap in one open round.
  maybeSimulateStep(send_buf.size() * common::utils::FIELDSIZE * peers.size());
  sendFieldVectorToPeers(peers, send_buf);

  std::vector<OpenPair> sums = local_pairs;
  auto recv_all = recvFieldVectorsFromPeers(peers, send_buf.size());
  for (const auto& recv_buf : recv_all) {
    for (size_t i = 0; i < local_pairs.size(); ++i) {
      sums[i].d += recv_buf[2 * i];
      sums[i].e += recv_buf[2 * i + 1];
    }
  }
  return sums;
}

Field Protocol::openToComputingParties(const Field& local_share) const {
  if (id_ >= helper_id_) {
    return Field(0);
  }

  const auto peers = computingPeerIdsExcludingSelf();
  std::vector<Field> local_vec = {local_share};
  // Full-duplex model: this open is one round (send+recv overlap).
  maybeSimulateStep(common::utils::FIELDSIZE * peers.size());
  sendFieldVectorToPeers(peers, local_vec);

  Field opened = local_share;
  auto recv_all = recvFieldVectorsFromPeers(peers, 1);
  for (const auto& recv_vec : recv_all) {
    opened += recv_vec[0];
  }
  return opened;
}

std::vector<Field> Protocol::openVectorToComputingParties(const std::vector<Field>& local_vec) const {
  if (id_ >= helper_id_) {
    return {};
  }
  if (local_vec.empty()) {
    return {};
  }

  const auto peers = computingPeerIdsExcludingSelf();
  std::vector<Field> opened = local_vec;
  const size_t bytes = local_vec.size() * common::utils::FIELDSIZE;
  // Full-duplex model: this batched open is one round (send+recv overlap).
  maybeSimulateStep(bytes * peers.size());
  sendFieldVectorToPeers(peers, local_vec);

  auto recv_all = recvFieldVectorsFromPeers(peers, local_vec.size());
  for (const auto& recv_buf : recv_all) {
    for (size_t i = 0; i < local_vec.size(); ++i) {
      opened[i] += recv_buf[i];
    }
  }
  return opened;
}

std::vector<Field> Protocol::batchedTruncateAll(const Field& x_share, size_t lx,
                                                size_t s, BGTEZStats* stats) {
  auto off = compare_offline(lx, s);
  if (id_ >= helper_id_) {
    return {};
  }
  if (!off.trunc_data.ready) {
    throw std::runtime_error("batchedTruncateAll requires ready truncation offline data");
  }
  std::vector<Field> c_local(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
    Field z = x_share + ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
    c_local[j - 1] =
        z + NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) * off.trunc_data.r_share[j - 1] +
        off.trunc_data.r0_share[j - 1];
  }
  auto c_open = openVectorToComputingParties(c_local);
  if (stats != nullptr) {
    stats->batched_open_calls += 1;
  }

  std::vector<Field> u(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c_open[j - 1]));
    const uint64_t c0 = c_u64 & (two_pow_j - 1);
    Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) -
              off.trunc_data.r0_share[j - 1];
    const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
    u[j - 1] = inv2pow * (x_share - d);
  }
  return u;
}

std::vector<Field> Protocol::serialTruncateAllForTesting(const Field& x_share, size_t lx, size_t s,
                                                         BGTEZStats* stats) {
  if (lx == 0) {
    throw std::runtime_error("serialTruncateAllForTesting requires lx > 0");
  }
  auto cmp_off = compare_offline(lx, s);
  if (id_ >= helper_id_) {
    return {};
  }

  std::vector<Field> out(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
    Field z = x_share + ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
    Field c_local =
        z + NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) * cmp_off.trunc_data.r_share[j - 1] +
        cmp_off.trunc_data.r0_share[j - 1];
    Field c_open = openToComputingParties(c_local);
    const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c_open));
    const uint64_t c0 = c_u64 & (two_pow_j - 1);
    Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) -
              cmp_off.trunc_data.r0_share[j - 1];
    const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
    out[j - 1] = inv2pow * (x_share - d);
    if (stats != nullptr) {
      stats->batched_open_calls += 1;
    }
  }
  return out;
}

Field Protocol::bgtezCompare(const Field& x_share, size_t lx, size_t s, bool force_t,
                             bool forced_t_value, BGTEZStats* stats) {
  auto off = compare_offline(lx, s, force_t, forced_t_value);
  return compare_online(x_share, off, stats);
}

void Protocol::maybeSimulateStep(size_t aggregate_bytes) const {
  maybeSimulateLatency();
  maybeSimulateBandwidth(aggregate_bytes);
}

void Protocol::maybeSimulateLatency() const {
  if (config_.sim_latency_ms > 0) {
    std::this_thread::sleep_for(std::chrono::duration<double, std::milli>(
        config_.sim_latency_ms));
  }
}

void Protocol::maybeSimulateBandwidth(size_t bytes) const {
  if (config_.sim_bandwidth_mbps <= 0 || bytes == 0) {
    return;
  }
  const double bits = static_cast<double>(bytes) * 8.0;
  const double seconds = bits / (config_.sim_bandwidth_mbps * 1e6);
  if (seconds > 0) {
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
  }
}

}  // namespace asterisk2
