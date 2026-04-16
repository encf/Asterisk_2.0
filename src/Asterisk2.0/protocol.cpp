#include "protocol.h"

#include <algorithm>
#include <array>
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
  kTruncMalRShare = 0x54524d4c52534852ULL,
  kTruncMalR0Share = 0x54524d4c52305348ULL,
  kTruncMalDeltaRShare = 0x54524d4c44525348ULL,
  kTruncMalDeltaR0Share = 0x54524d4c44523053ULL,
  kCmpMask = 0x434d504d41534b53ULL,
  kCmpShuffle = 0x434d505348554646ULL,
  kCmpBit = 0x434d504249545f5fULL,
  kCmpHelperShare = 0x434d504853484152ULL,
  kCmpMalOutShare = 0x434d504d4f555453ULL,
  kCmpMalDeltaOutShare = 0x434d504d444f5554ULL,
  kEqzHelperShare = 0x45515a4853484152ULL,
  kEqzMalOutShare = 0x45515a4d4f555453ULL,
  kEqzMalDeltaOutShare = 0x45515a4d444f5554ULL,
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

std::array<Field, 4> deriveOfflineMaskShare(const PairwiseKey& pairwise_key, uint64_t idx,
                                            uint64_t bound_r, uint64_t bound_r0) {
  auto r_prg = makePrgFromPairwiseKey(pairwise_key, idx, PrgLabel::kTruncMalRShare);
  auto r0_prg = makePrgFromPairwiseKey(pairwise_key, idx, PrgLabel::kTruncMalR0Share);
  auto dr_prg = makePrgFromPairwiseKey(pairwise_key, idx, PrgLabel::kTruncMalDeltaRShare);
  auto dr0_prg = makePrgFromPairwiseKey(pairwise_key, idx, PrgLabel::kTruncMalDeltaR0Share);
  return {prgFieldBounded(r_prg, bound_r), prgFieldBounded(r0_prg, bound_r0), prgField(dr_prg),
          prgField(dr0_prg)};
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
      wire_share_(circ_.num_gates, Field(0)) {
  if (config_.security_model == SecurityModel::kMalicious) {
    initializeMaliciousMacSetup();
  }
}

void Protocol::initializeMaliciousMacSetup() {
  if (malicious_mac_setup_ready_) {
    return;
  }
  const auto mac_setup = runMacSetupDH(nP_, id_, network_, key_manager_, seed_);
  if (id_ < helper_id_) {
    malicious_delta_share_ = mac_setup.party.delta_share;
    malicious_delta_inv_share_ = mac_setup.party.delta_inv_share;
  } else if (id_ == helper_id_) {
    helper_delta_ = mac_setup.helper.delta;
    helper_delta_inv_ = mac_setup.helper.delta_inv;
  }
  malicious_mac_setup_ready_ = true;
}

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
  if (!malicious_mac_setup_ready_) {
    throw std::runtime_error("malicious MAC setup not initialized");
  }
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

  if (id_ < helper_id_) {
    out.delta_share = malicious_delta_share_;
    out.delta_inv_share = malicious_delta_inv_share_;
  } else if (id_ == helper_id_) {
    out.helper_delta = helper_delta_;
    out.helper_delta_inv = helper_delta_inv_;
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

std::vector<Field> Protocol::mul_online_semi_honest_batch(
    const std::vector<Field>& x_shares, const std::vector<Field>& y_shares,
    const std::vector<const MulOfflineData*>& offline_data_vec) {
  if (x_shares.size() != y_shares.size() || x_shares.size() != offline_data_vec.size()) {
    throw std::runtime_error("mul_online_semi_honest_batch input size mismatch");
  }
  if (id_ >= helper_id_) {
    return {};
  }
  if (x_shares.empty()) {
    return {};
  }

  std::vector<Field> opened_batch;
  opened_batch.reserve(2 * x_shares.size());
  for (size_t i = 0; i < x_shares.size(); ++i) {
    const auto* offline_data = offline_data_vec[i];
    if (offline_data == nullptr || !offline_data->ready || offline_data->triples.empty()) {
      throw std::runtime_error("mul_online_semi_honest_batch requires ready single-gate offline data");
    }
    const auto& t = offline_data->triples[0];
    opened_batch.push_back(x_shares[i] - t.a);
    opened_batch.push_back(y_shares[i] - t.b);
  }

  const auto opened = openVectorToComputingParties(opened_batch);
  if (opened.size() != opened_batch.size()) {
    throw std::runtime_error("mul_online_semi_honest_batch batched-open failed");
  }

  std::vector<Field> outputs(x_shares.size(), Field(0));
  for (size_t i = 0; i < x_shares.size(); ++i) {
    const auto& t = offline_data_vec[i]->triples[0];
    const Field d = opened[2 * i];
    const Field e = opened[2 * i + 1];
    outputs[i] = e * t.a + d * t.b + t.c;
    if (id_ == 0) {
      outputs[i] += d * e;
    }
  }
  return outputs;
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
      for (size_t i = 0; i < mul_gates.size(); ++i) {
        if (mul_idx + i >= offline_data.triples.size()) {
          throw std::runtime_error("Insufficient Beaver triples in mul_online phase");
        }
        const auto* g = mul_gates[i];
        const auto& t = offline_data.triples[mul_idx + i];
        const Field d_share = wire_share_[g->in1] - t.a;
        const Field e_share = wire_share_[g->in2] - t.b;
        const auto opened = openVectorToComputingParties({d_share, e_share});
        if (opened.size() != 2) {
          throw std::runtime_error("semi-honest online open failed");
        }
        const Field d = opened[0];
        const Field e = opened[1];
        Field out = e * t.a + d * t.b + t.c;
        if (id_ == 0) {
          out += d * e;
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
      const Field f_share = offline_data.delta_inv_share - auth.c_prime;
      const std::vector<Field> opened_batch =
          openVectorToComputingParties({d_share, e_share, d_delta_share, e_delta_share, f_share});
      if (opened_batch.size() != 5) {
        throw std::runtime_error("malicious online batched-open failed");
      }
      const Field d = opened_batch[0];
      const Field e = opened_batch[1];
      const Field d_delta = opened_batch[2];
      const Field e_delta = opened_batch[3];
      const Field f = opened_batch[4];

      Field xy_share = e * t.a + d * t.b + t.c;
      if (id_ == 0) {
        xy_share += d * e;
      }

      Field delta_xy_share =
          auth.c_prime * d_delta * e_delta + auth.a_prime * e_delta * f +
          auth.b_prime * d_delta * f + auth.a_prime_c_prime * e_delta +
          auth.b_prime_c_prime * d_delta + auth.a_prime_b_prime * f +
          auth.a_prime_b_prime_c_prime;
      if (id_ == 0) {
        delta_xy_share += d_delta * e_delta * f;
      }

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

  if (malicious_key_material_verified_) {
    return;
  }

  const Field delta = openToComputingParties(offline_data.delta_share);
  const Field delta_inv = openToComputingParties(offline_data.delta_inv_share);
  if (delta == Field(0) || delta * delta_inv != Field(1)) {
    throw std::runtime_error("malicious key-material consistency check failed");
  }
  malicious_key_material_verified_ = true;
}

TruncOfflineData Protocol::trunc_offline(size_t batch_size, size_t ell_x, size_t m, size_t s) {
  if (config_.security_model == SecurityModel::kMalicious) {
    return trunc_offline_malicious(batch_size, ell_x, m, s);
  }
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

TruncOfflineData Protocol::trunc_offline_malicious(size_t batch_size, size_t ell_x, size_t m,
                                                   size_t s) {
  if (id_ > helper_id_) {
    return {};
  }
  if (m == 0 || m > ell_x) {
    throw std::runtime_error("trunc_offline_malicious requires 0 < m <= ell_x");
  }
  if (ell_x + s + 1 >= 64) {
    throw std::runtime_error("trunc_offline_malicious requires ell_x + s + 1 < 64");
  }
  if (!malicious_mac_setup_ready_) {
    throw std::runtime_error("trunc_offline_malicious requires malicious MAC setup");
  }

  TruncOfflineData off;
  off.ell_x = ell_x;
  off.m = m;
  off.s = s;
  off.r_share.assign(batch_size, Field(0));
  off.r0_share.assign(batch_size, Field(0));
  off.delta_r_share.assign(batch_size, Field(0));
  off.delta_r0_share.assign(batch_size, Field(0));

  const uint64_t bound_r = pow2Bound(ell_x - m + s);
  const uint64_t bound_r0 = pow2Bound(m);

  if (id_ == helper_id_) {
    for (size_t idx = 0; idx < batch_size; ++idx) {
      auto helper_prg = makePrg(seed_, helper_id_, idx, PrgLabel::kTruncHelper);
      const Field r = prgFieldBounded(helper_prg, bound_r);
      const Field r0 = prgFieldBounded(helper_prg, bound_r0);
      const Field delta_r = helper_delta_ * r;
      const Field delta_r0 = helper_delta_ * r0;

      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      Field sum_delta_r = Field(0);
      Field sum_delta_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        const auto share =
            deriveOfflineMaskShare(key_manager_.keyForParty(i), idx, bound_r, bound_r0);
        sum_r += share[0];
        sum_r0 += share[1];
        sum_delta_r += share[2];
        sum_delta_r0 += share[3];
      }

      Field pack[4] = {r - sum_r, r0 - sum_r0, delta_r - sum_delta_r,
                       delta_r0 - sum_delta_r0};
      network_->send(nP_ - 1, pack, 4 * common::utils::FIELDSIZE);
    }
    network_->flush();
    off.ready = true;
    return off;
  }

  if (id_ <= nP_ - 2) {
    const auto pairwise_key = key_manager_.keyWithHelper();
    for (size_t idx = 0; idx < batch_size; ++idx) {
      const auto share = deriveOfflineMaskShare(pairwise_key, idx, bound_r, bound_r0);
      off.r_share[idx] = share[0];
      off.r0_share[idx] = share[1];
      off.delta_r_share[idx] = share[2];
      off.delta_r0_share[idx] = share[3];
    }
    off.delta_share = malicious_delta_share_;
  } else if (id_ == nP_ - 1) {
    for (size_t idx = 0; idx < batch_size; ++idx) {
      Field pack[4];
      network_->recv(helper_id_, pack, 4 * common::utils::FIELDSIZE);
      off.r_share[idx] = pack[0];
      off.r0_share[idx] = pack[1];
      off.delta_r_share[idx] = pack[2];
      off.delta_r0_share[idx] = pack[3];
    }
    off.delta_share = malicious_delta_share_;
  }

  off.ready = true;
  return off;
}

std::vector<Field> Protocol::trunc_online(const std::vector<Field>& x_shares,
                                          const TruncOfflineData& offline_data) {
  if (config_.security_model == SecurityModel::kMalicious) {
    throw std::runtime_error(
        "trunc_online in malicious mode requires trunc_online_malicious with [x] and [Δx]");
  }
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

AuthTruncResult Protocol::trunc_online_malicious(const std::vector<Field>& x_shares,
                                                 const std::vector<Field>& delta_x_shares,
                                                 const TruncOfflineData& offline_data) {
  AuthTruncResult out;
  if (id_ > helper_id_) {
    return out;
  }
  if (!offline_data.ready) {
    throw std::runtime_error("trunc_online_malicious requires ready TruncOfflineData");
  }
  if (x_shares.size() != delta_x_shares.size() || offline_data.r_share.size() != x_shares.size() ||
      offline_data.r0_share.size() != x_shares.size() ||
      offline_data.delta_r_share.size() != x_shares.size() ||
      offline_data.delta_r0_share.size() != x_shares.size()) {
    throw std::runtime_error("trunc_online_malicious input/offline vector sizes mismatch");
  }
  if (offline_data.m == 0 || offline_data.m > offline_data.ell_x) {
    throw std::runtime_error("trunc_online_malicious invalid truncation parameters");
  }

  const uint64_t two_pow_m = pow2Bound(offline_data.m);
  const uint64_t two_pow_lx_minus_1 = pow2Bound(offline_data.ell_x - 1);
  const Field two_pow_m_field = NTL::conv<Field>(NTL::to_ZZ(two_pow_m));
  const Field shift_field = NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1));
  const Field lambda_m = inv(two_pow_m_field);

  out.trunc_x_shares.assign(x_shares.size(), Field(0));
  out.trunc_delta_x_shares.assign(x_shares.size(), Field(0));

  for (size_t idx = 0; idx < x_shares.size(); ++idx) {
    const Field z_i = x_shares[idx] + ((id_ == 0) ? shift_field : Field(0));
    const Field delta_z_i = delta_x_shares[idx] + offline_data.delta_share * shift_field;

    const Field c_i = z_i + two_pow_m_field * offline_data.r_share[idx] + offline_data.r0_share[idx];
    const Field delta_c_i =
        delta_z_i + two_pow_m_field * offline_data.delta_r_share[idx] + offline_data.delta_r0_share[idx];
    const Field c = openToComputingParties(c_i);

    if (id_ < helper_id_) {
      const Field c_dc_i = offline_data.delta_share * c - delta_c_i;
      network_->send(helper_id_, &c_dc_i, common::utils::FIELDSIZE);
      network_->flush();
    } else {
      Field sum = Field(0);
      for (int p = 0; p < helper_id_; ++p) {
        Field recv = Field(0);
        network_->recv(p, &recv, common::utils::FIELDSIZE);
        sum += recv;
      }
      const uint8_t ok = (sum == Field(0)) ? 1 : 0;
      for (int p = 0; p < helper_id_; ++p) {
        network_->send(p, &ok, sizeof(ok));
      }
      network_->flush();
      if (ok == 0) {
        throw std::runtime_error("trunc_online_malicious consistency check failed");
      }
      continue;
    }

    uint8_t verdict = 0;
    network_->recv(helper_id_, &verdict, sizeof(verdict));
    if (verdict == 0) {
      throw std::runtime_error("trunc_online_malicious aborted by helper");
    }

    const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c));
    const uint64_t c0 = c_u64 & (two_pow_m - 1);
    const Field c0_field = NTL::conv<Field>(NTL::to_ZZ(c0));
    const Field d_i = ((id_ == 0) ? c0_field : Field(0)) - offline_data.r0_share[idx];
    const Field delta_d_i = offline_data.delta_share * c0_field - offline_data.delta_r0_share[idx];
    out.trunc_x_shares[idx] = lambda_m * (x_shares[idx] - d_i);
    out.trunc_delta_x_shares[idx] = lambda_m * (delta_x_shares[idx] - delta_d_i);
  }

  return out;
}

CompareOfflineData Protocol::compare_offline_internal(size_t lx, size_t s, bool force_t,
                                                      bool forced_t_value,
                                                      uint64_t domain_sep) {
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
      const uint64_t mask_idx = (domain_sep << 32) | static_cast<uint64_t>(j);
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto helper_prg = makePrg(seed_, helper_id_, mask_idx, PrgLabel::kTruncHelper);
      Field r = prgFieldBounded(helper_prg, bound_r);
      Field r0 = prgFieldBounded(helper_prg, bound_r0);
      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto pprg = makePrgFromPairwiseKey(key_manager_.keyForParty(i), mask_idx,
                                           PrgLabel::kTruncShare);
        sum_r += prgFieldBounded(pprg, bound_r);
        sum_r0 += prgFieldBounded(pprg, bound_r0);
      }
      pack[2 * (j - 1)] = r - sum_r;
      pack[2 * (j - 1) + 1] = r0 - sum_r0;
    }
    network_->send(nP_ - 1, pack.data(), pack.size() * common::utils::FIELDSIZE);
    network_->flush();
  } else if (id_ <= nP_ - 2) {
    const auto pairwise_key = key_manager_.keyWithHelper();
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t mask_idx = (domain_sep << 32) | static_cast<uint64_t>(j);
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto pprg = makePrgFromPairwiseKey(pairwise_key, mask_idx, PrgLabel::kTruncShare);
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
  out.domain_sep = domain_sep;

  out.cmp_data.rho.assign(lx + 2, Field(0));
  out.cmp_data.permutation.resize(lx + 2);
  std::iota(out.cmp_data.permutation.begin(), out.cmp_data.permutation.end(), 0);
  out.cmp_data.t = false;

  // K_P: key shared among computing parties only, used to derive shared compare
  // randomness in compare_offline.
  if (id_ < helper_id_) {
    const auto kp = key_manager_.computingPartiesKey();
    for (size_t i = 0; i < out.cmp_data.rho.size(); ++i) {
      const uint64_t mask_idx = (domain_sep << 32) | static_cast<uint64_t>(i + 1);
      auto pprg = makePrgFromPairwiseKey(kp, mask_idx, PrgLabel::kCmpMask);
      out.cmp_data.rho[i] = prgNonZeroField(pprg);
    }

    auto shuffle_prg =
        makePrgFromPairwiseKey(kp, (domain_sep << 32) | static_cast<uint64_t>(lx),
                               PrgLabel::kCmpShuffle);
    for (size_t i = out.cmp_data.permutation.size(); i > 1; --i) {
      size_t j = static_cast<size_t>(prgUint64(shuffle_prg) % i);
      std::swap(out.cmp_data.permutation[i - 1], out.cmp_data.permutation[j]);
    }

    if (force_t) {
      out.cmp_data.t = forced_t_value;
    } else {
      auto t_prg =
          makePrgFromPairwiseKey(kp, (domain_sep << 32) | static_cast<uint64_t>(lx + 1),
                                 PrgLabel::kCmpBit);
      out.cmp_data.t = prgBit(t_prg);
    }
  }

  out.domain_sep = domain_sep;
  out.cmp_data.ready = true;
  out.ready = true;
  return out;
}

CompareOfflineData Protocol::compare_offline(size_t lx, size_t s, bool force_t,
                                             bool forced_t_value) {
  return compare_offline_internal(lx, s, force_t, forced_t_value, 0);
}

CompareOfflineData Protocol::compare_offline_tagged(size_t lx, size_t s, uint64_t domain_sep,
                                                    bool force_t, bool forced_t_value) {
  return compare_offline_internal(lx, s, force_t, forced_t_value, domain_sep);
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

    Field partial = Field(0);
    for (int p = 0; p <= helper_id_ - 2; ++p) {
      auto prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p), offline_data.domain_sep,
                                        PrgLabel::kCmpHelperShare);
      partial += prgField(prg);
    }
    const Field residual_share = bit - partial;

    // Round 3: parties 0..n-2 derive their output shares locally from the
    // helper pairwise key, so only the residual share for the last party is sent.
    std::vector<uint8_t> payload(common::utils::FIELDSIZE);
    NTL::BytesFromZZ(payload.data(), NTL::conv<NTL::ZZ>(residual_share), common::utils::FIELDSIZE);
    auto* channel = network_->getSendChannel(helper_id_ - 1);
    channel->send_data(payload.data(), payload.size());
    channel->flush();
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
    auto* channel = network_->getSendChannel(helper_id_);
    channel->send_data(payload.data(), payload.size());
    channel->flush();
  }

  // Round 3: parties 0..n-2 derive their shares locally; the last party
  // receives the residual share from the helper.
  Field bit_share = Field(0);
  if (id_ <= helper_id_ - 2) {
    auto prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(), offline_data.domain_sep,
                                      PrgLabel::kCmpHelperShare);
    bit_share = prgField(prg);
  } else {
    std::vector<uint8_t> recv_payload(common::utils::FIELDSIZE);
    auto* recv_channel = network_->getRecvChannel(helper_id_);
    recv_channel->recv_data(recv_payload.data(), recv_payload.size());
    bit_share = NTL::conv<Field>(
        NTL::ZZFromBytes(recv_payload.data(), common::utils::FIELDSIZE));
  }
  Field t_share = (id_ == 0 && t) ? Field(1) : Field(0);
  return t_share + bit_share - Field(2) * (t ? bit_share : Field(0));
}

std::vector<Field> Protocol::compare_online_batch(
    const std::vector<Field>& x_shares,
    const std::vector<const CompareOfflineData*>& offline_data_vec,
    BGTEZStats* stats) {
  if (x_shares.size() != offline_data_vec.size()) {
    throw std::runtime_error("compare_online_batch input size mismatch");
  }
  if (x_shares.empty()) {
    return {};
  }

  size_t lx = 0;
  size_t s = 0;
  for (size_t i = 0; i < offline_data_vec.size(); ++i) {
    const auto* offline_data = offline_data_vec[i];
    if (offline_data == nullptr || !offline_data->ready || !offline_data->trunc_data.ready ||
        !offline_data->cmp_data.ready) {
      throw std::runtime_error("compare_online_batch requires ready CompareOfflineData");
    }
    if (i == 0) {
      lx = offline_data->trunc_data.lx;
      s = offline_data->trunc_data.s;
      if (lx == 0 || lx + s + 1 >= 64) {
        throw std::runtime_error("compare_online_batch got invalid offline truncation parameters");
      }
    } else if (offline_data->trunc_data.lx != lx || offline_data->trunc_data.s != s) {
      throw std::runtime_error("compare_online_batch requires matching truncation parameters");
    }
  }

  if (id_ > helper_id_) {
    return std::vector<Field>(x_shares.size(), Field(0));
  }

  const size_t batch_size = x_shares.size();
  const size_t helper_payload_len_per_cmp = lx + 3;

  if (id_ == helper_id_) {
    std::vector<int> peers;
    peers.reserve(static_cast<size_t>(helper_id_));
    for (int p = 0; p < helper_id_; ++p) {
      peers.push_back(p);
    }
    const size_t total_helper_payload_len = batch_size * helper_payload_len_per_cmp;
    const size_t bytes = total_helper_payload_len * common::utils::FIELDSIZE;
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

    std::vector<Field> sum(total_helper_payload_len, Field(0));
    for (const auto& buf : recv_payloads) {
      auto vals = deserializeFieldVector(buf);
      for (size_t i = 0; i < vals.size(); ++i) {
        sum[i] += vals[i];
      }
    }

    std::vector<Field> residual_shares(batch_size, Field(0));
    for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
      const size_t offset = cmp_idx * helper_payload_len_per_cmp;
      bool any_zero = false;
      for (size_t i = 0; i < helper_payload_len_per_cmp; ++i) {
        if (sum[offset + i] == Field(0)) {
          any_zero = true;
          break;
        }
      }
      const uint64_t opened_raw = NTL::conv<uint64_t>(NTL::rep(sum[offset + lx + 2]));
      int64_t opened_x = static_cast<int64_t>(opened_raw);
      if (opened_raw > (kPrime64Minus59 / 2ULL)) {
        opened_x = static_cast<int64_t>(opened_raw - kPrime64Minus59);
      }
      const Field bit = (opened_x >= 0 || any_zero) ? Field(1) : Field(0);

      Field partial = Field(0);
      for (int p = 0; p <= helper_id_ - 2; ++p) {
        auto prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p),
                                          offline_data_vec[cmp_idx]->domain_sep,
                                          PrgLabel::kCmpHelperShare);
        partial += prgField(prg);
      }
      residual_shares[cmp_idx] = bit - partial;
    }

    auto payload = serializeFieldVector(residual_shares);
    auto* channel = network_->getSendChannel(helper_id_ - 1);
    channel->send_data(payload.data(), payload.size());
    channel->flush();
    return std::vector<Field>(batch_size, Field(0));
  }

  std::vector<Field> c_local(batch_size * lx, Field(0));
  std::vector<Field> hat_x(batch_size, Field(0));
  std::vector<bool> t(batch_size, false);
  std::vector<Field> u_star(batch_size, Field(0));
  for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
    t[cmp_idx] = offline_data_vec[cmp_idx]->cmp_data.t;
    hat_x[cmp_idx] = t[cmp_idx] ? -x_shares[cmp_idx] : x_shares[cmp_idx];
    u_star[cmp_idx] = (id_ == 0) ? (t[cmp_idx] ? Field(-1) : Field(1)) : Field(0);
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t two_pow_j = pow2Bound(j);
      const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
      Field z = hat_x[cmp_idx] +
                ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
      c_local[cmp_idx * lx + (j - 1)] =
          z +
          NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) *
              offline_data_vec[cmp_idx]->trunc_data.r_share[j - 1] +
          offline_data_vec[cmp_idx]->trunc_data.r0_share[j - 1];
    }
  }

  auto c_open = openVectorToComputingParties(c_local);
  if (stats != nullptr) {
    stats->batched_open_calls += 1;
  }
  if (c_open.size() != c_local.size()) {
    throw std::runtime_error("compare_online_batch batched opening size mismatch");
  }

  std::vector<Field> helper_payload(batch_size * helper_payload_len_per_cmp, Field(0));
  const Field one_share = (id_ == 0) ? Field(1) : Field(0);
  for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
    std::vector<Field> u_all(lx + 1, Field(0));
    u_all[0] = hat_x[cmp_idx];
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t two_pow_j = pow2Bound(j);
      const uint64_t c_u64 =
          NTL::conv<uint64_t>(NTL::rep(c_open[cmp_idx * lx + (j - 1)]));
      const uint64_t c0 = c_u64 & (two_pow_j - 1);
      Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) -
                offline_data_vec[cmp_idx]->trunc_data.r0_share[j - 1];
      const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
      u_all[j] = inv2pow * (hat_x[cmp_idx] - d);
    }

    Field v_star = u_star[cmp_idx] + Field(3) * u_all[0] - one_share;
    std::vector<Field> candidates(lx + 2, Field(0));
    candidates[0] = offline_data_vec[cmp_idx]->cmp_data.rho[0] * v_star;
    for (size_t j = 0; j <= lx; ++j) {
      Field sum = Field(0);
      for (size_t k = j; k <= lx; ++k) {
        sum += u_all[k];
      }
      candidates[j + 1] =
          offline_data_vec[cmp_idx]->cmp_data.rho[j + 1] * (sum - one_share);
    }

    const size_t offset = cmp_idx * helper_payload_len_per_cmp;
    for (size_t i = 0; i < candidates.size(); ++i) {
      helper_payload[offset + i] =
          candidates[offline_data_vec[cmp_idx]->cmp_data.permutation[i]];
    }
    helper_payload[offset + lx + 2] = hat_x[cmp_idx];
  }

  auto payload = serializeFieldVector(helper_payload);
  auto* channel = network_->getSendChannel(helper_id_);
  channel->send_data(payload.data(), payload.size());
  channel->flush();

  std::vector<Field> bit_shares(batch_size, Field(0));
  if (id_ <= helper_id_ - 2) {
    for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
      auto prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(),
                                        offline_data_vec[cmp_idx]->domain_sep,
                                        PrgLabel::kCmpHelperShare);
      bit_shares[cmp_idx] = prgField(prg);
    }
  } else {
    std::vector<uint8_t> recv_payload(batch_size * common::utils::FIELDSIZE);
    auto* recv_channel = network_->getRecvChannel(helper_id_);
    recv_channel->recv_data(recv_payload.data(), recv_payload.size());
    bit_shares = deserializeFieldVector(recv_payload);
  }

  std::vector<Field> outputs(batch_size, Field(0));
  for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
    const Field t_share = (id_ == 0 && t[cmp_idx]) ? Field(1) : Field(0);
    outputs[cmp_idx] = t_share + bit_shares[cmp_idx] -
                       Field(2) * (t[cmp_idx] ? bit_shares[cmp_idx] : Field(0));
  }
  return outputs;
}

EqzOfflineData Protocol::eqz_offline(size_t lx, size_t s) {
  return eqz_offline_tagged(lx, s, 0);
}

EqzOfflineData Protocol::eqz_offline_tagged(size_t lx, size_t s, uint64_t domain_sep) {
  EqzOfflineData out;
  const uint64_t base = (domain_sep << 2) | 1ULL;
  out.nonneg_data = compare_offline_internal(lx, s, false, false, base);
  out.nonpos_data = compare_offline_internal(lx, s, false, false, base + 1);
  out.domain_sep = domain_sep;
  out.ready = out.nonneg_data.ready && out.nonpos_data.ready;
  return out;
}

Field Protocol::eqz_online(const Field& x_share, const EqzOfflineData& offline_data,
                           BGTEZStats* stats) {
  if (!offline_data.ready || !offline_data.nonneg_data.ready || !offline_data.nonpos_data.ready) {
    throw std::runtime_error("eqz_online requires ready EqzOfflineData");
  }
  const size_t lx = offline_data.nonneg_data.trunc_data.lx;
  const size_t s = offline_data.nonneg_data.trunc_data.s;
  if (lx == 0 || lx + s + 1 >= 64) {
    throw std::runtime_error("eqz_online got invalid offline truncation parameters");
  }
  if (offline_data.nonpos_data.trunc_data.lx != lx ||
      offline_data.nonpos_data.trunc_data.s != s) {
    throw std::runtime_error("eqz_online requires matching truncation parameters");
  }

  if (id_ > helper_id_) {
    return Field(0);
  }

  constexpr size_t kEqzCmpCount = 2;
  const size_t helper_payload_len_per_cmp = lx + 3;
  const size_t total_helper_payload_len = kEqzCmpCount * helper_payload_len_per_cmp;

  if (id_ == helper_id_) {
    std::vector<int> peers;
    peers.reserve(static_cast<size_t>(helper_id_));
    for (int p = 0; p < helper_id_; ++p) {
      peers.push_back(p);
    }

    const size_t bytes = total_helper_payload_len * common::utils::FIELDSIZE;
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

    std::vector<Field> sum(total_helper_payload_len, Field(0));
    for (const auto& buf : recv_payloads) {
      auto vals = deserializeFieldVector(buf);
      for (size_t i = 0; i < vals.size(); ++i) {
        sum[i] += vals[i];
      }
    }

    auto decode_bit = [&](size_t cmp_idx) {
      const size_t offset = cmp_idx * helper_payload_len_per_cmp;
      bool any_zero = false;
      for (size_t i = 0; i < lx + 2; ++i) {
        if (sum[offset + i] == Field(0)) {
          any_zero = true;
          break;
        }
      }
      return any_zero ? Field(1) : Field(0);
    };

    const Field nonneg_prime = decode_bit(0);
    const Field nonpos_prime = decode_bit(1);
    const Field dprime =
        nonneg_prime + nonpos_prime - Field(2) * nonneg_prime * nonpos_prime;
    Field residual = dprime;
    for (int p = 0; p <= helper_id_ - 2; ++p) {
      auto prg =
        makePrgFromPairwiseKey(key_manager_.keyForParty(p), offline_data.domain_sep,
                               PrgLabel::kEqzHelperShare);
      residual -= prgField(prg);
    }

    std::vector<uint8_t> payload(common::utils::FIELDSIZE);
    NTL::BytesFromZZ(payload.data(), NTL::conv<NTL::ZZ>(residual), common::utils::FIELDSIZE);
    auto* channel = network_->getSendChannel(helper_id_ - 1);
    channel->send_data(payload.data(), payload.size());
    channel->flush();
    return Field(0);
  }

  const std::array<const CompareOfflineData*, kEqzCmpCount> off = {
      &offline_data.nonneg_data, &offline_data.nonpos_data};
  const std::array<Field, kEqzCmpCount> inputs = {x_share, -x_share};

  std::array<Field, kEqzCmpCount> hat_x = {Field(0), Field(0)};
  std::array<Field, kEqzCmpCount> u_star = {Field(0), Field(0)};
  std::vector<Field> c_local(kEqzCmpCount * lx, Field(0));
  for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
    const bool t = off[cmp_idx]->cmp_data.t;
    hat_x[cmp_idx] = t ? -inputs[cmp_idx] : inputs[cmp_idx];
    u_star[cmp_idx] = (id_ == 0) ? (t ? Field(-1) : Field(1)) : Field(0);
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t two_pow_j = pow2Bound(j);
      const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
      Field z = hat_x[cmp_idx] +
                ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
      c_local[cmp_idx * lx + (j - 1)] =
          z + NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) * off[cmp_idx]->trunc_data.r_share[j - 1] +
          off[cmp_idx]->trunc_data.r0_share[j - 1];
    }
  }

  auto c_open = openVectorToComputingParties(c_local);
  if (stats != nullptr) {
    stats->batched_open_calls += 1;
  }
  if (c_open.size() != kEqzCmpCount * lx) {
    throw std::runtime_error("eqz_online batched opening size mismatch");
  }

  std::array<std::vector<Field>, kEqzCmpCount> u_trunc = {
      std::vector<Field>(lx, Field(0)), std::vector<Field>(lx, Field(0))};
  for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t two_pow_j = pow2Bound(j);
      const uint64_t c_u64 =
          NTL::conv<uint64_t>(NTL::rep(c_open[cmp_idx * lx + (j - 1)]));
      const uint64_t c0 = c_u64 & (two_pow_j - 1);
      Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) -
                off[cmp_idx]->trunc_data.r0_share[j - 1];
      const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
      u_trunc[cmp_idx][j - 1] = inv2pow * (hat_x[cmp_idx] - d);
    }
  }

  std::vector<Field> helper_payload(total_helper_payload_len, Field(0));
  Field one_share = (id_ == 0) ? Field(1) : Field(0);
  for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
    std::vector<Field> u_all(lx + 1, Field(0));
    u_all[0] = hat_x[cmp_idx];
    for (size_t j = 1; j <= lx; ++j) {
      u_all[j] = u_trunc[cmp_idx][j - 1];
    }

    Field v_star = u_star[cmp_idx] + Field(3) * hat_x[cmp_idx] - one_share;
    std::vector<Field> candidates(lx + 2, Field(0));
    candidates[0] = off[cmp_idx]->cmp_data.rho[0] * v_star;
    for (size_t j = 0; j <= lx; ++j) {
      Field sum = Field(0);
      for (size_t k = j; k <= lx; ++k) {
        sum += u_all[k];
      }
      candidates[j + 1] =
          off[cmp_idx]->cmp_data.rho[j + 1] * (sum - one_share);
    }

    const size_t offset = cmp_idx * helper_payload_len_per_cmp;
    for (size_t i = 0; i < candidates.size(); ++i) {
      helper_payload[offset + i] =
          candidates[off[cmp_idx]->cmp_data.permutation[i]];
    }
    helper_payload[offset + lx + 2] = hat_x[cmp_idx];
  }

  auto payload = serializeFieldVector(helper_payload);
  auto* channel = network_->getSendChannel(helper_id_);
  channel->send_data(payload.data(), payload.size());
  channel->flush();

  Field dprime_share = Field(0);
  if (id_ <= helper_id_ - 2) {
    auto prg =
        makePrgFromPairwiseKey(key_manager_.keyWithHelper(), offline_data.domain_sep,
                               PrgLabel::kEqzHelperShare);
    dprime_share = prgField(prg);
  } else {
    std::vector<uint8_t> recv_payload(common::utils::FIELDSIZE);
    auto* recv_channel = network_->getRecvChannel(helper_id_);
    recv_channel->recv_data(recv_payload.data(), recv_payload.size());
    dprime_share =
        NTL::conv<Field>(NTL::ZZFromBytes(recv_payload.data(), common::utils::FIELDSIZE));
  }

  const bool tprime = off[0]->cmp_data.t ^ off[1]->cmp_data.t;
  return tprime ? dprime_share : (one_share - dprime_share);
}

std::vector<Field> Protocol::eqz_online_batch(
    const std::vector<Field>& x_shares,
    const std::vector<const EqzOfflineData*>& offline_data_vec,
    BGTEZStats* stats) {
  if (x_shares.size() != offline_data_vec.size()) {
    throw std::runtime_error("eqz_online_batch input size mismatch");
  }
  if (x_shares.empty()) {
    return {};
  }

  size_t lx = 0;
  size_t s = 0;
  for (size_t i = 0; i < offline_data_vec.size(); ++i) {
    const auto* offline_data = offline_data_vec[i];
    if (offline_data == nullptr || !offline_data->ready || !offline_data->nonneg_data.ready ||
        !offline_data->nonpos_data.ready) {
      throw std::runtime_error("eqz_online_batch requires ready EqzOfflineData");
    }
    if (i == 0) {
      lx = offline_data->nonneg_data.trunc_data.lx;
      s = offline_data->nonneg_data.trunc_data.s;
      if (lx == 0 || lx + s + 1 >= 64) {
        throw std::runtime_error("eqz_online_batch got invalid offline truncation parameters");
      }
    }
    if (offline_data->nonneg_data.trunc_data.lx != lx ||
        offline_data->nonneg_data.trunc_data.s != s ||
        offline_data->nonpos_data.trunc_data.lx != lx ||
        offline_data->nonpos_data.trunc_data.s != s) {
      throw std::runtime_error("eqz_online_batch requires matching truncation parameters");
    }
  }

  if (id_ > helper_id_) {
    return std::vector<Field>(x_shares.size(), Field(0));
  }

  constexpr size_t kEqzCmpCount = 2;
  const size_t batch_size = x_shares.size();
  const size_t helper_payload_len_per_cmp = lx + 3;
  const size_t total_helper_payload_len = batch_size * kEqzCmpCount * helper_payload_len_per_cmp;

  if (id_ == helper_id_) {
    std::vector<int> peers;
    peers.reserve(static_cast<size_t>(helper_id_));
    for (int p = 0; p < helper_id_; ++p) {
      peers.push_back(p);
    }

    const size_t bytes = total_helper_payload_len * common::utils::FIELDSIZE;
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

    std::vector<Field> sum(total_helper_payload_len, Field(0));
    for (const auto& buf : recv_payloads) {
      auto vals = deserializeFieldVector(buf);
      for (size_t i = 0; i < vals.size(); ++i) {
        sum[i] += vals[i];
      }
    }

    std::vector<Field> residual_shares(batch_size, Field(0));
    for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
      auto decode_bit = [&](size_t cmp_idx) {
        const size_t offset =
            (eqz_idx * kEqzCmpCount + cmp_idx) * helper_payload_len_per_cmp;
        bool any_zero = false;
        for (size_t i = 0; i < lx + 2; ++i) {
          if (sum[offset + i] == Field(0)) {
            any_zero = true;
            break;
          }
        }
        return any_zero ? Field(1) : Field(0);
      };

      const Field nonneg_prime = decode_bit(0);
      const Field nonpos_prime = decode_bit(1);
      const Field dprime =
          nonneg_prime + nonpos_prime - Field(2) * nonneg_prime * nonpos_prime;
      Field residual = dprime;
      for (int p = 0; p <= helper_id_ - 2; ++p) {
        auto prg =
            makePrgFromPairwiseKey(key_manager_.keyForParty(p),
                                   offline_data_vec[eqz_idx]->domain_sep,
                                   PrgLabel::kEqzHelperShare);
        residual -= prgField(prg);
      }
      residual_shares[eqz_idx] = residual;
    }

    auto payload = serializeFieldVector(residual_shares);
    auto* channel = network_->getSendChannel(helper_id_ - 1);
    channel->send_data(payload.data(), payload.size());
    channel->flush();
    return std::vector<Field>(batch_size, Field(0));
  }

  std::vector<Field> c_local(batch_size * kEqzCmpCount * lx, Field(0));
  std::vector<Field> helper_payload(total_helper_payload_len, Field(0));
  const Field one_share = (id_ == 0) ? Field(1) : Field(0);
  for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
    const std::array<const CompareOfflineData*, kEqzCmpCount> off = {
        &offline_data_vec[eqz_idx]->nonneg_data, &offline_data_vec[eqz_idx]->nonpos_data};
    const std::array<Field, kEqzCmpCount> inputs = {x_shares[eqz_idx], -x_shares[eqz_idx]};
    std::array<Field, kEqzCmpCount> hat_x = {Field(0), Field(0)};
    std::array<Field, kEqzCmpCount> u_star = {Field(0), Field(0)};

    for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
      const bool t = off[cmp_idx]->cmp_data.t;
      hat_x[cmp_idx] = t ? -inputs[cmp_idx] : inputs[cmp_idx];
      u_star[cmp_idx] = (id_ == 0) ? (t ? Field(-1) : Field(1)) : Field(0);
      for (size_t j = 1; j <= lx; ++j) {
        const uint64_t two_pow_j = pow2Bound(j);
        const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
        Field z = hat_x[cmp_idx] +
                  ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
        c_local[(eqz_idx * kEqzCmpCount + cmp_idx) * lx + (j - 1)] =
            z + NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) * off[cmp_idx]->trunc_data.r_share[j - 1] +
            off[cmp_idx]->trunc_data.r0_share[j - 1];
      }
    }
  }

  auto c_open = openVectorToComputingParties(c_local);
  if (stats != nullptr) {
    stats->batched_open_calls += 1;
  }
  if (c_open.size() != c_local.size()) {
    throw std::runtime_error("eqz_online_batch batched opening size mismatch");
  }

  for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
    const std::array<const CompareOfflineData*, kEqzCmpCount> off = {
        &offline_data_vec[eqz_idx]->nonneg_data, &offline_data_vec[eqz_idx]->nonpos_data};
    const std::array<Field, kEqzCmpCount> inputs = {x_shares[eqz_idx], -x_shares[eqz_idx]};
    std::array<Field, kEqzCmpCount> hat_x = {Field(0), Field(0)};
    std::array<Field, kEqzCmpCount> u_star = {Field(0), Field(0)};

    for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
      const bool t = off[cmp_idx]->cmp_data.t;
      hat_x[cmp_idx] = t ? -inputs[cmp_idx] : inputs[cmp_idx];
      u_star[cmp_idx] = (id_ == 0) ? (t ? Field(-1) : Field(1)) : Field(0);
      std::vector<Field> u_all(lx + 1, Field(0));
      u_all[0] = hat_x[cmp_idx];
      for (size_t j = 1; j <= lx; ++j) {
        const uint64_t two_pow_j = pow2Bound(j);
        const uint64_t c_u64 = NTL::conv<uint64_t>(
            NTL::rep(c_open[(eqz_idx * kEqzCmpCount + cmp_idx) * lx + (j - 1)]));
        const uint64_t c0 = c_u64 & (two_pow_j - 1);
        Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) -
                  off[cmp_idx]->trunc_data.r0_share[j - 1];
        const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
        u_all[j] = inv2pow * (hat_x[cmp_idx] - d);
      }

      Field v_star = u_star[cmp_idx] + Field(3) * u_all[0] - one_share;
      std::vector<Field> candidates(lx + 2, Field(0));
      candidates[0] = off[cmp_idx]->cmp_data.rho[0] * v_star;
      for (size_t j = 0; j <= lx; ++j) {
        Field sum = Field(0);
        for (size_t k = j; k <= lx; ++k) {
          sum += u_all[k];
        }
        candidates[j + 1] = off[cmp_idx]->cmp_data.rho[j + 1] * (sum - one_share);
      }

      const size_t offset =
          (eqz_idx * kEqzCmpCount + cmp_idx) * helper_payload_len_per_cmp;
      for (size_t i = 0; i < candidates.size(); ++i) {
        helper_payload[offset + i] = candidates[off[cmp_idx]->cmp_data.permutation[i]];
      }
      helper_payload[offset + lx + 2] = hat_x[cmp_idx];
    }
  }

  auto payload = serializeFieldVector(helper_payload);
  auto* channel = network_->getSendChannel(helper_id_);
  channel->send_data(payload.data(), payload.size());
  channel->flush();

  std::vector<Field> dprime_shares(batch_size, Field(0));
  if (id_ <= helper_id_ - 2) {
    for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
      auto prg =
          makePrgFromPairwiseKey(key_manager_.keyWithHelper(),
                                 offline_data_vec[eqz_idx]->domain_sep,
                                 PrgLabel::kEqzHelperShare);
      dprime_shares[eqz_idx] = prgField(prg);
    }
  } else {
    std::vector<uint8_t> recv_payload(batch_size * common::utils::FIELDSIZE);
    auto* recv_channel = network_->getRecvChannel(helper_id_);
    recv_channel->recv_data(recv_payload.data(), recv_payload.size());
    dprime_shares = deserializeFieldVector(recv_payload);
  }

  std::vector<Field> outputs(batch_size, Field(0));
  for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
    const bool tprime = offline_data_vec[eqz_idx]->nonneg_data.cmp_data.t ^
                        offline_data_vec[eqz_idx]->nonpos_data.cmp_data.t;
    outputs[eqz_idx] = tprime ? dprime_shares[eqz_idx] : (one_share - dprime_shares[eqz_idx]);
  }
  return outputs;
}

CompareOfflineDataMalicious Protocol::compare_offline_malicious_internal(
    size_t lx, size_t s, bool force_t, bool forced_t_value, uint64_t domain_sep) {
  if (lx == 0) {
    throw std::runtime_error("compare_offline_malicious requires lx > 0");
  }
  if (lx + s + 1 >= 64) {
    throw std::runtime_error("compare_offline_malicious requires lx + s + 1 < 64");
  }
  if (!malicious_mac_setup_ready_) {
    throw std::runtime_error("compare_offline_malicious requires malicious MAC setup");
  }
  if (id_ > helper_id_) {
    return {};
  }

  CompareOfflineDataMalicious out;
  out.lx = lx;
  out.s = s;
  out.r_share.assign(lx, Field(0));
  out.r0_share.assign(lx, Field(0));
  out.delta_r_share.assign(lx, Field(0));
  out.delta_r0_share.assign(lx, Field(0));
  out.cmp_data.rho.assign(lx + 2, Field(0));
  out.cmp_data.permutation.resize(lx + 2);
  std::iota(out.cmp_data.permutation.begin(), out.cmp_data.permutation.end(), 0);

  if (id_ == helper_id_) {
    std::vector<Field> pack(4 * lx, Field(0));
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t mask_idx = (domain_sep << 32) | static_cast<uint64_t>(j);
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto helper_prg = makePrg(seed_, helper_id_, mask_idx, PrgLabel::kTruncHelper);
      const Field r = prgFieldBounded(helper_prg, bound_r);
      const Field r0 = prgFieldBounded(helper_prg, bound_r0);
      const Field delta_r = helper_delta_ * r;
      const Field delta_r0 = helper_delta_ * r0;

      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      Field sum_delta_r = Field(0);
      Field sum_delta_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        const auto share =
            deriveOfflineMaskShare(key_manager_.keyForParty(i), mask_idx, bound_r, bound_r0);
        sum_r += share[0];
        sum_r0 += share[1];
        sum_delta_r += share[2];
        sum_delta_r0 += share[3];
      }
      pack[4 * (j - 1)] = r - sum_r;
      pack[4 * (j - 1) + 1] = r0 - sum_r0;
      pack[4 * (j - 1) + 2] = delta_r - sum_delta_r;
      pack[4 * (j - 1) + 3] = delta_r0 - sum_delta_r0;
    }
    network_->send(nP_ - 1, pack.data(), pack.size() * common::utils::FIELDSIZE);
    network_->flush();
  } else if (id_ <= nP_ - 2) {
    const auto pairwise_key = key_manager_.keyWithHelper();
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t mask_idx = (domain_sep << 32) | static_cast<uint64_t>(j);
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      const auto share = deriveOfflineMaskShare(pairwise_key, mask_idx, bound_r, bound_r0);
      out.r_share[j - 1] = share[0];
      out.r0_share[j - 1] = share[1];
      out.delta_r_share[j - 1] = share[2];
      out.delta_r0_share[j - 1] = share[3];
    }
  } else if (id_ == nP_ - 1) {
    std::vector<Field> pack(4 * lx, Field(0));
    network_->recv(helper_id_, pack.data(), pack.size() * common::utils::FIELDSIZE);
    for (size_t j = 0; j < lx; ++j) {
      out.r_share[j] = pack[4 * j];
      out.r0_share[j] = pack[4 * j + 1];
      out.delta_r_share[j] = pack[4 * j + 2];
      out.delta_r0_share[j] = pack[4 * j + 3];
    }
  }

  if (id_ < helper_id_) {
    out.delta_share = malicious_delta_share_;
    const auto kp = key_manager_.computingPartiesKey();
    for (size_t i = 0; i < out.cmp_data.rho.size(); ++i) {
      const uint64_t mask_idx = (domain_sep << 32) | static_cast<uint64_t>(i + 1);
      auto pprg = makePrgFromPairwiseKey(kp, mask_idx, PrgLabel::kCmpMask);
      out.cmp_data.rho[i] = prgNonZeroField(pprg);
    }
    auto shuffle_prg =
        makePrgFromPairwiseKey(kp, (domain_sep << 32) | static_cast<uint64_t>(lx),
                               PrgLabel::kCmpShuffle);
    for (size_t i = out.cmp_data.permutation.size(); i > 1; --i) {
      size_t j = static_cast<size_t>(prgUint64(shuffle_prg) % i);
      std::swap(out.cmp_data.permutation[i - 1], out.cmp_data.permutation[j]);
    }
    if (force_t) {
      out.cmp_data.t = forced_t_value;
    } else {
      auto t_prg =
          makePrgFromPairwiseKey(kp, (domain_sep << 32) | static_cast<uint64_t>(lx + 1),
                                 PrgLabel::kCmpBit);
      out.cmp_data.t = prgBit(t_prg);
    }
  }

  out.cmp_data.ready = true;
  out.ready = true;
  return out;
}

CompareOfflineDataMalicious Protocol::compare_offline_malicious(size_t lx, size_t s, bool force_t,
                                                                bool forced_t_value) {
  return compare_offline_malicious_internal(lx, s, force_t, forced_t_value, 0);
}

CompareOfflineDataMalicious Protocol::compare_offline_malicious_tagged(
    size_t lx, size_t s, uint64_t domain_sep, bool force_t, bool forced_t_value) {
  return compare_offline_malicious_internal(lx, s, force_t, forced_t_value, domain_sep);
}

AuthMulResult Protocol::mul_online_malicious_single(
    const Field& x_share, const Field& delta_x_share, const Field& y_share,
    const Field& delta_y_share, const MulOfflineData& offline_data) {
  AuthMulResult out;
  verifyMaliciousKeyMaterial(offline_data);
  if (id_ >= helper_id_) {
    return out;
  }
  if (!offline_data.ready || offline_data.triples.empty() || offline_data.auth_tuples.empty()) {
    throw std::runtime_error("mul_online_malicious_single requires ready single-gate offline data");
  }

  const auto& t = offline_data.triples[0];
  const auto& auth = offline_data.auth_tuples[0];

  const Field d_share = x_share - t.a;
  const Field e_share = y_share - t.b;
  const Field d_delta_share = delta_x_share - auth.a_prime;
  const Field e_delta_share = delta_y_share - auth.b_prime;
  const Field f_share = offline_data.delta_inv_share - auth.c_prime;
  const std::vector<Field> opened_batch =
      openVectorToComputingParties({d_share, e_share, d_delta_share, e_delta_share, f_share});
  if (opened_batch.size() != 5) {
    throw std::runtime_error("mul_online_malicious_single batched-open failed");
  }

  const Field d = opened_batch[0];
  const Field e = opened_batch[1];
  const Field d_delta = opened_batch[2];
  const Field e_delta = opened_batch[3];
  const Field f = opened_batch[4];

  out.share = e * t.a + d * t.b + t.c;
  if (id_ == 0) {
    out.share += d * e;
  }

  out.delta_share = auth.c_prime * d_delta * e_delta + auth.a_prime * e_delta * f +
                    auth.b_prime * d_delta * f + auth.a_prime_c_prime * e_delta +
                    auth.b_prime_c_prime * d_delta + auth.a_prime_b_prime * f +
                    auth.a_prime_b_prime_c_prime;
  if (id_ == 0) {
    out.delta_share += d_delta * e_delta * f;
  }
  return out;
}

std::vector<AuthMulResult> Protocol::mul_online_malicious_batch(
    const std::vector<Field>& x_shares, const std::vector<Field>& delta_x_shares,
    const std::vector<Field>& y_shares, const std::vector<Field>& delta_y_shares,
    const std::vector<const MulOfflineData*>& offline_data_vec) {
  if (x_shares.size() != delta_x_shares.size() || x_shares.size() != y_shares.size() ||
      x_shares.size() != delta_y_shares.size() || x_shares.size() != offline_data_vec.size()) {
    throw std::runtime_error("mul_online_malicious_batch input size mismatch");
  }
  std::vector<AuthMulResult> outputs(x_shares.size());
  if (x_shares.empty() || id_ >= helper_id_) {
    return outputs;
  }

  std::vector<Field> opened_batch;
  opened_batch.reserve(5 * x_shares.size());
  for (size_t i = 0; i < x_shares.size(); ++i) {
    const auto* offline_data = offline_data_vec[i];
    if (offline_data == nullptr || !offline_data->ready || offline_data->triples.empty() ||
        offline_data->auth_tuples.empty()) {
      throw std::runtime_error("mul_online_malicious_batch requires ready single-gate offline data");
    }
    verifyMaliciousKeyMaterial(*offline_data);
    const auto& t = offline_data->triples[0];
    const auto& auth = offline_data->auth_tuples[0];
    opened_batch.push_back(x_shares[i] - t.a);
    opened_batch.push_back(y_shares[i] - t.b);
    opened_batch.push_back(delta_x_shares[i] - auth.a_prime);
    opened_batch.push_back(delta_y_shares[i] - auth.b_prime);
    opened_batch.push_back(offline_data->delta_inv_share - auth.c_prime);
  }

  const auto opened = openVectorToComputingParties(opened_batch);
  if (opened.size() != opened_batch.size()) {
    throw std::runtime_error("mul_online_malicious_batch batched-open failed");
  }

  for (size_t i = 0; i < x_shares.size(); ++i) {
    const auto& t = offline_data_vec[i]->triples[0];
    const auto& auth = offline_data_vec[i]->auth_tuples[0];
    const Field d = opened[5 * i];
    const Field e = opened[5 * i + 1];
    const Field d_delta = opened[5 * i + 2];
    const Field e_delta = opened[5 * i + 3];
    const Field f = opened[5 * i + 4];

    outputs[i].share = e * t.a + d * t.b + t.c;
    if (id_ == 0) {
      outputs[i].share += d * e;
    }

    outputs[i].delta_share =
        auth.c_prime * d_delta * e_delta + auth.a_prime * e_delta * f +
        auth.b_prime * d_delta * f + auth.a_prime_c_prime * e_delta +
        auth.b_prime_c_prime * d_delta + auth.a_prime_b_prime * f +
        auth.a_prime_b_prime_c_prime;
    if (id_ == 0) {
      outputs[i].delta_share += d_delta * e_delta * f;
    }
  }
  return outputs;
}

AuthCompareResult Protocol::compare_online_malicious(
    const Field& x_share, const Field& delta_x_share,
    const CompareOfflineDataMalicious& offline_data) {
  AuthCompareResult out;
  if (id_ > helper_id_) {
    return out;
  }
  if (!offline_data.ready || !offline_data.cmp_data.ready) {
    throw std::runtime_error("compare_online_malicious requires ready malicious offline data");
  }
  const size_t lx = offline_data.lx;
  const size_t s = offline_data.s;
  if (lx == 0 || lx + s + 1 >= 64) {
    throw std::runtime_error("compare_online_malicious got invalid truncation parameters");
  }
  if (offline_data.r_share.size() != lx || offline_data.r0_share.size() != lx ||
      offline_data.delta_r_share.size() != lx || offline_data.delta_r0_share.size() != lx) {
    throw std::runtime_error("compare_online_malicious offline vector sizes mismatch");
  }
  if (id_ < helper_id_ &&
      (offline_data.cmp_data.rho.size() != lx + 2 ||
       offline_data.cmp_data.permutation.size() != lx + 2)) {
    throw std::runtime_error("compare_online_malicious compare mask/permutation size mismatch");
  }

  if (id_ == helper_id_) {
    // Round 2: helper receives all batched check values and compare payloads.
    const size_t payload_len = lx + 2 * (lx + 2) + 1;
    std::vector<Field> sum_cdc(lx, Field(0));
    std::vector<Field> sum_w(lx + 2, Field(0));
    std::vector<Field> sum_delta_w(lx + 2, Field(0));
    Field sum_hat_x = Field(0);
    for (int p = 0; p < helper_id_; ++p) {
      std::vector<Field> recv(payload_len, Field(0));
      network_->recv(p, recv.data(), payload_len * common::utils::FIELDSIZE);
      for (size_t j = 0; j < lx; ++j) {
        sum_cdc[j] += recv[j];
      }
      for (size_t k = 0; k < lx + 2; ++k) {
        sum_w[k] += recv[lx + k];
        sum_delta_w[k] += recv[lx + (lx + 2) + k];
      }
      sum_hat_x += recv.back();
    }

    bool ok = true;
    for (const auto& cdc : sum_cdc) {
      ok = ok && (cdc == Field(0));
    }
    for (size_t k = 0; k < lx + 2; ++k) {
      ok = ok && (helper_delta_ * sum_w[k] == sum_delta_w[k]);
    }

    uint8_t verdict = ok ? 1 : 0;
    Field gtez_prime = Field(0);
    Field delta_gtez_prime = Field(0);
    if (ok) {
      bool any_zero = false;
      for (const auto& wk : sum_w) {
        any_zero = any_zero || (wk == Field(0));
      }
      const uint64_t opened_raw = NTL::conv<uint64_t>(NTL::rep(sum_hat_x));
      int64_t opened_hat_x = static_cast<int64_t>(opened_raw);
      if (opened_raw > (kPrime64Minus59 / 2ULL)) {
        opened_hat_x = static_cast<int64_t>(opened_raw - kPrime64Minus59);
      }
      gtez_prime = (any_zero || opened_hat_x >= 0) ? Field(1) : Field(0);
      delta_gtez_prime = helper_delta_ * gtez_prime;
    }

    Field sum_g = Field(0);
    Field sum_dg = Field(0);
    std::vector<Field> g_share(helper_id_, Field(0));
    std::vector<Field> dg_share(helper_id_, Field(0));
    for (int p = 0; p <= helper_id_ - 2; ++p) {
      auto g_prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p), offline_data.domain_sep,
                                          PrgLabel::kCmpMalOutShare);
      auto dg_prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p), offline_data.domain_sep,
                                           PrgLabel::kCmpMalDeltaOutShare);
      g_share[p] = prgField(g_prg);
      dg_share[p] = prgField(dg_prg);
      sum_g += g_share[p];
      sum_dg += dg_share[p];
    }
    g_share[helper_id_ - 1] = gtez_prime - sum_g;
    dg_share[helper_id_ - 1] = delta_gtez_prime - sum_dg;

    // Round 3: helper broadcasts the verdict to all parties, while only the
    // last party receives the residual output share pair.
    for (int p = 0; p < helper_id_; ++p) {
      auto* ch = network_->getSendChannel(p);
      ch->send_data(&verdict, sizeof(verdict));
      if (p == helper_id_ - 1 && verdict == 1) {
        std::vector<uint8_t> residual_payload(2 * common::utils::FIELDSIZE, 0);
        NTL::BytesFromZZ(residual_payload.data(), NTL::conv<NTL::ZZ>(g_share[p]),
                         common::utils::FIELDSIZE);
        NTL::BytesFromZZ(residual_payload.data() + common::utils::FIELDSIZE,
                         NTL::conv<NTL::ZZ>(dg_share[p]), common::utils::FIELDSIZE);
        ch->send_data(residual_payload.data(), residual_payload.size());
      }
      ch->flush();
    }
    return out;
  }

  // Round 1: batch-open all c^(j) for truncation.
  const Field sign = (id_ < helper_id_ && offline_data.cmp_data.t) ? Field(-1) : Field(1);
  const Field one_share = (id_ == 0) ? Field(1) : Field(0);
  const Field x_hat = x_share * sign;
  const Field delta_x_hat = delta_x_share * sign;
  const Field u_star = one_share * sign;
  const Field delta_u_star = offline_data.delta_share * sign;
  const Field shift_field = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(lx - 1)));
  const Field z_i = x_hat + one_share * shift_field;
  const Field delta_z_i = delta_x_hat + offline_data.delta_share * shift_field;

  std::vector<Field> c_local(lx, Field(0));
  std::vector<Field> delta_c_local(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const Field two_pow_j = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(j)));
    c_local[j - 1] = z_i + two_pow_j * offline_data.r_share[j - 1] + offline_data.r0_share[j - 1];
    delta_c_local[j - 1] =
        delta_z_i + two_pow_j * offline_data.delta_r_share[j - 1] + offline_data.delta_r0_share[j - 1];
  }
  const auto c_open = openVectorToComputingParties(c_local);
  if (c_open.size() != lx) {
    throw std::runtime_error("compare_online_malicious opening size mismatch");
  }

  std::vector<Field> u(lx + 1, Field(0));
  std::vector<Field> delta_u(lx + 1, Field(0));
  std::vector<Field> c_dc(lx, Field(0));
  u[0] = x_hat;
  delta_u[0] = delta_x_hat;
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
    const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c_open[j - 1]));
    const Field c0_field = NTL::conv<Field>(NTL::to_ZZ(c_u64 & (two_pow_j - 1)));
    const Field d_i = one_share * c0_field - offline_data.r0_share[j - 1];
    const Field delta_d_i = offline_data.delta_share * c0_field - offline_data.delta_r0_share[j - 1];
    u[j] = inv2pow * (x_hat - d_i);
    delta_u[j] = inv2pow * (delta_x_hat - delta_d_i);
    c_dc[j - 1] = offline_data.delta_share * c_open[j - 1] - delta_c_local[j - 1];
  }

  // Round 2: send all c_dc^(j) and shuffled (w_k, delta_w_k) to helper.
  std::vector<Field> v(lx + 1, Field(0));
  std::vector<Field> delta_v(lx + 1, Field(0));
  Field v_star = u_star + Field(3) * u[0] - one_share;
  Field delta_v_star = delta_u_star + Field(3) * delta_u[0] - offline_data.delta_share;
  for (size_t j = 0; j <= lx; ++j) {
    Field sum = Field(0);
    Field delta_sum = Field(0);
    for (size_t k = j; k <= lx; ++k) {
      sum += u[k];
      delta_sum += delta_u[k];
    }
    v[j] = sum - one_share;
    delta_v[j] = delta_sum - offline_data.delta_share;
  }

  std::vector<Field> w_tmp(lx + 2, Field(0));
  std::vector<Field> delta_w_tmp(lx + 2, Field(0));
  w_tmp[0] = offline_data.cmp_data.rho[0] * v_star;
  delta_w_tmp[0] = offline_data.cmp_data.rho[0] * delta_v_star;
  for (size_t j = 0; j <= lx; ++j) {
    w_tmp[j + 1] = offline_data.cmp_data.rho[j + 1] * v[j];
    delta_w_tmp[j + 1] = offline_data.cmp_data.rho[j + 1] * delta_v[j];
  }
  std::vector<Field> w(w_tmp.size(), Field(0));
  std::vector<Field> delta_w(delta_w_tmp.size(), Field(0));
  for (size_t i = 0; i < w_tmp.size(); ++i) {
    const size_t pos = offline_data.cmp_data.permutation[i];
    w[i] = w_tmp[pos];
    delta_w[i] = delta_w_tmp[pos];
  }

  if (id_ < helper_id_) {
    std::vector<Field> payload;
    payload.reserve(lx + 2 * (lx + 2) + 1);
    payload.insert(payload.end(), c_dc.begin(), c_dc.end());
    payload.insert(payload.end(), w.begin(), w.end());
    payload.insert(payload.end(), delta_w.begin(), delta_w.end());
    payload.push_back(x_hat);
    auto bytes = serializeFieldVector(payload);
    auto* channel = network_->getSendChannel(helper_id_);
    channel->send_data(bytes.data(), bytes.size());
    channel->flush();
  }

  uint8_t verdict = 0;
  network_->recv(helper_id_, &verdict, sizeof(verdict));
  if (verdict == 0) {
    throw std::runtime_error("compare_online_malicious aborted by helper");
  }

  Field gtez_prime_share = Field(0);
  Field delta_gtez_prime_share = Field(0);
  if (id_ <= helper_id_ - 2) {
    auto g_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(), offline_data.domain_sep,
                                        PrgLabel::kCmpMalOutShare);
    auto dg_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(), offline_data.domain_sep,
                                         PrgLabel::kCmpMalDeltaOutShare);
    gtez_prime_share = prgField(g_prg);
    delta_gtez_prime_share = prgField(dg_prg);
  } else {
    std::vector<uint8_t> residual_payload(2 * common::utils::FIELDSIZE, 0);
    network_->recv(helper_id_, residual_payload.data(), residual_payload.size());
    gtez_prime_share = NTL::conv<Field>(
        NTL::ZZFromBytes(residual_payload.data(), common::utils::FIELDSIZE));
    delta_gtez_prime_share = NTL::conv<Field>(
        NTL::ZZFromBytes(residual_payload.data() + common::utils::FIELDSIZE,
                         common::utils::FIELDSIZE));
  }

  const bool t = offline_data.cmp_data.t;
  const Field t_share = (id_ == 0 && t) ? Field(1) : Field(0);
  const Field delta_t_share = t ? offline_data.delta_share : Field(0);
  out.gtez_share = t_share + gtez_prime_share - Field(2) * (t ? gtez_prime_share : Field(0));
  out.delta_gtez_share =
      delta_t_share + delta_gtez_prime_share - Field(2) * (t ? delta_gtez_prime_share : Field(0));
  return out;
}

std::vector<AuthCompareResult> Protocol::compare_online_malicious_batch(
    const std::vector<Field>& x_shares, const std::vector<Field>& delta_x_shares,
    const std::vector<const CompareOfflineDataMalicious*>& offline_data_vec) {
  if (x_shares.size() != delta_x_shares.size() || x_shares.size() != offline_data_vec.size()) {
    throw std::runtime_error("compare_online_malicious_batch input size mismatch");
  }
  std::vector<AuthCompareResult> outputs(x_shares.size());
  if (x_shares.empty() || id_ > helper_id_) {
    return outputs;
  }

  size_t lx = 0;
  size_t s = 0;
  for (size_t i = 0; i < offline_data_vec.size(); ++i) {
    const auto* offline_data = offline_data_vec[i];
    if (offline_data == nullptr || !offline_data->ready || !offline_data->cmp_data.ready) {
      throw std::runtime_error("compare_online_malicious_batch requires ready malicious offline data");
    }
    if (i == 0) {
      lx = offline_data->lx;
      s = offline_data->s;
      if (lx == 0 || lx + s + 1 >= 64) {
        throw std::runtime_error(
            "compare_online_malicious_batch got invalid truncation parameters");
      }
    } else if (offline_data->lx != lx || offline_data->s != s) {
      throw std::runtime_error(
          "compare_online_malicious_batch requires matching truncation parameters");
    }
    if (offline_data->r_share.size() != lx || offline_data->r0_share.size() != lx ||
        offline_data->delta_r_share.size() != lx || offline_data->delta_r0_share.size() != lx) {
      throw std::runtime_error(
          "compare_online_malicious_batch offline vector sizes mismatch");
    }
    if (id_ < helper_id_ &&
        (offline_data->cmp_data.rho.size() != lx + 2 ||
         offline_data->cmp_data.permutation.size() != lx + 2)) {
      throw std::runtime_error(
          "compare_online_malicious_batch compare mask/permutation size mismatch");
    }
  }

  const size_t batch_size = x_shares.size();
  const size_t payload_len_per_cmp = lx + 2 * (lx + 2) + 1;

  if (id_ == helper_id_) {
    const size_t total_payload_len = batch_size * payload_len_per_cmp;
    std::vector<Field> sum_payload(total_payload_len, Field(0));
    for (int p = 0; p < helper_id_; ++p) {
      std::vector<Field> recv(total_payload_len, Field(0));
      network_->recv(p, recv.data(), total_payload_len * common::utils::FIELDSIZE);
      for (size_t i = 0; i < total_payload_len; ++i) {
        sum_payload[i] += recv[i];
      }
    }

    bool verdict = true;
    std::vector<Field> g_share(batch_size, Field(0));
    std::vector<Field> dg_share(batch_size, Field(0));
    if (verdict) {
      for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
        const size_t base = cmp_idx * payload_len_per_cmp;
        for (size_t j = 0; j < lx; ++j) {
          verdict = verdict && (sum_payload[base + j] == Field(0));
        }
        for (size_t k = 0; k < lx + 2; ++k) {
          verdict = verdict &&
                    (helper_delta_ * sum_payload[base + lx + k] ==
                     sum_payload[base + lx + (lx + 2) + k]);
        }
      }
    }

    if (verdict) {
      for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
        const size_t base = cmp_idx * payload_len_per_cmp;
        bool any_zero = false;
        for (size_t k = 0; k < lx + 2; ++k) {
          any_zero = any_zero || (sum_payload[base + lx + k] == Field(0));
        }
        const uint64_t opened_raw = NTL::conv<uint64_t>(NTL::rep(sum_payload[base + payload_len_per_cmp - 1]));
        int64_t opened_hat_x = static_cast<int64_t>(opened_raw);
        if (opened_raw > (kPrime64Minus59 / 2ULL)) {
          opened_hat_x = static_cast<int64_t>(opened_raw - kPrime64Minus59);
        }
        const Field gtez_prime = (any_zero || opened_hat_x >= 0) ? Field(1) : Field(0);
        const Field delta_gtez_prime = helper_delta_ * gtez_prime;

        Field sum_g = Field(0);
        Field sum_dg = Field(0);
        for (int p = 0; p <= helper_id_ - 2; ++p) {
          auto g_prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p),
                                              offline_data_vec[cmp_idx]->domain_sep,
                                              PrgLabel::kCmpMalOutShare);
          auto dg_prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p),
                                               offline_data_vec[cmp_idx]->domain_sep,
                                               PrgLabel::kCmpMalDeltaOutShare);
          sum_g += prgField(g_prg);
          sum_dg += prgField(dg_prg);
        }
        g_share[cmp_idx] = gtez_prime - sum_g;
        dg_share[cmp_idx] = delta_gtez_prime - sum_dg;
      }
    }

    const uint8_t verdict_byte = verdict ? 1 : 0;
    for (int p = 0; p < helper_id_; ++p) {
      auto* ch = network_->getSendChannel(p);
      ch->send_data(&verdict_byte, sizeof(verdict_byte));
      if (p == helper_id_ - 1 && verdict) {
        std::vector<Field> residual_payload;
        residual_payload.reserve(2 * batch_size);
        for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
          residual_payload.push_back(g_share[cmp_idx]);
          residual_payload.push_back(dg_share[cmp_idx]);
        }
        auto bytes = serializeFieldVector(residual_payload);
        ch->send_data(bytes.data(), bytes.size());
      }
      ch->flush();
    }
    return outputs;
  }

  const Field one_share = (id_ == 0) ? Field(1) : Field(0);
  std::vector<Field> c_local(batch_size * lx, Field(0));
  std::vector<Field> delta_c_local(batch_size * lx, Field(0));
  std::vector<Field> x_hat(batch_size, Field(0));
  std::vector<Field> delta_x_hat(batch_size, Field(0));
  std::vector<Field> u_star(batch_size, Field(0));
  std::vector<Field> delta_u_star(batch_size, Field(0));
  for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
    const Field sign =
        (id_ < helper_id_ && offline_data_vec[cmp_idx]->cmp_data.t) ? Field(-1) : Field(1);
    x_hat[cmp_idx] = x_shares[cmp_idx] * sign;
    delta_x_hat[cmp_idx] = delta_x_shares[cmp_idx] * sign;
    u_star[cmp_idx] = one_share * sign;
    delta_u_star[cmp_idx] = offline_data_vec[cmp_idx]->delta_share * sign;
    const Field shift_field = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(lx - 1)));
    const Field z_i = x_hat[cmp_idx] + one_share * shift_field;
    const Field delta_z_i =
        delta_x_hat[cmp_idx] + offline_data_vec[cmp_idx]->delta_share * shift_field;
    for (size_t j = 1; j <= lx; ++j) {
      const Field two_pow_j = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(j)));
      c_local[cmp_idx * lx + (j - 1)] =
          z_i + two_pow_j * offline_data_vec[cmp_idx]->r_share[j - 1] +
          offline_data_vec[cmp_idx]->r0_share[j - 1];
      delta_c_local[cmp_idx * lx + (j - 1)] =
          delta_z_i + two_pow_j * offline_data_vec[cmp_idx]->delta_r_share[j - 1] +
          offline_data_vec[cmp_idx]->delta_r0_share[j - 1];
    }
  }

  const auto c_open = openVectorToComputingParties(c_local);
  if (c_open.size() != c_local.size()) {
    throw std::runtime_error("compare_online_malicious_batch opening size mismatch");
  }

  std::vector<Field> payload;
  payload.reserve(batch_size * payload_len_per_cmp);
  for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
    std::vector<Field> u(lx + 1, Field(0));
    std::vector<Field> delta_u(lx + 1, Field(0));
    std::vector<Field> c_dc(lx, Field(0));
    u[0] = x_hat[cmp_idx];
    delta_u[0] = delta_x_hat[cmp_idx];
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t two_pow_j = pow2Bound(j);
      const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
      const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c_open[cmp_idx * lx + (j - 1)]));
      const Field c0_field = NTL::conv<Field>(NTL::to_ZZ(c_u64 & (two_pow_j - 1)));
      const Field d_i = one_share * c0_field - offline_data_vec[cmp_idx]->r0_share[j - 1];
      const Field delta_d_i =
          offline_data_vec[cmp_idx]->delta_share * c0_field -
          offline_data_vec[cmp_idx]->delta_r0_share[j - 1];
      u[j] = inv2pow * (x_hat[cmp_idx] - d_i);
      delta_u[j] = inv2pow * (delta_x_hat[cmp_idx] - delta_d_i);
      c_dc[j - 1] = offline_data_vec[cmp_idx]->delta_share * c_open[cmp_idx * lx + (j - 1)] -
                    delta_c_local[cmp_idx * lx + (j - 1)];
    }

    std::vector<Field> v(lx + 1, Field(0));
    std::vector<Field> delta_v(lx + 1, Field(0));
    const Field v_star = u_star[cmp_idx] + Field(3) * u[0] - one_share;
    const Field delta_v_star =
        delta_u_star[cmp_idx] + Field(3) * delta_u[0] - offline_data_vec[cmp_idx]->delta_share;
    for (size_t j = 0; j <= lx; ++j) {
      Field sum = Field(0);
      Field delta_sum = Field(0);
      for (size_t k = j; k <= lx; ++k) {
        sum += u[k];
        delta_sum += delta_u[k];
      }
      v[j] = sum - one_share;
      delta_v[j] = delta_sum - offline_data_vec[cmp_idx]->delta_share;
    }

    std::vector<Field> w_tmp(lx + 2, Field(0));
    std::vector<Field> delta_w_tmp(lx + 2, Field(0));
    w_tmp[0] = offline_data_vec[cmp_idx]->cmp_data.rho[0] * v_star;
    delta_w_tmp[0] = offline_data_vec[cmp_idx]->cmp_data.rho[0] * delta_v_star;
    for (size_t j = 0; j <= lx; ++j) {
      w_tmp[j + 1] = offline_data_vec[cmp_idx]->cmp_data.rho[j + 1] * v[j];
      delta_w_tmp[j + 1] =
          offline_data_vec[cmp_idx]->cmp_data.rho[j + 1] * delta_v[j];
    }
    std::vector<Field> w(w_tmp.size(), Field(0));
    std::vector<Field> delta_w(delta_w_tmp.size(), Field(0));
    for (size_t i = 0; i < w_tmp.size(); ++i) {
      const size_t pos = offline_data_vec[cmp_idx]->cmp_data.permutation[i];
      w[i] = w_tmp[pos];
      delta_w[i] = delta_w_tmp[pos];
    }

    payload.insert(payload.end(), c_dc.begin(), c_dc.end());
    payload.insert(payload.end(), w.begin(), w.end());
    payload.insert(payload.end(), delta_w.begin(), delta_w.end());
    payload.push_back(x_hat[cmp_idx]);
  }

  auto bytes = serializeFieldVector(payload);
  auto* channel = network_->getSendChannel(helper_id_);
  channel->send_data(bytes.data(), bytes.size());
  channel->flush();

  uint8_t verdict = 0;
  network_->recv(helper_id_, &verdict, sizeof(verdict));
  if (verdict == 0) {
    throw std::runtime_error("compare_online_malicious_batch aborted by helper");
  }

  std::vector<Field> gtez_prime_share(batch_size, Field(0));
  std::vector<Field> delta_gtez_prime_share(batch_size, Field(0));
  if (id_ <= helper_id_ - 2) {
    for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
      auto g_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(),
                                          offline_data_vec[cmp_idx]->domain_sep,
                                          PrgLabel::kCmpMalOutShare);
      auto dg_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(),
                                           offline_data_vec[cmp_idx]->domain_sep,
                                           PrgLabel::kCmpMalDeltaOutShare);
      gtez_prime_share[cmp_idx] = prgField(g_prg);
      delta_gtez_prime_share[cmp_idx] = prgField(dg_prg);
    }
  } else {
    std::vector<uint8_t> residual_payload(2 * batch_size * common::utils::FIELDSIZE, 0);
    network_->recv(helper_id_, residual_payload.data(), residual_payload.size());
    const auto residual_fields = deserializeFieldVector(residual_payload);
    if (residual_fields.size() != 2 * batch_size) {
      throw std::runtime_error("compare_online_malicious_batch residual size mismatch");
    }
    for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
      gtez_prime_share[cmp_idx] = residual_fields[2 * cmp_idx];
      delta_gtez_prime_share[cmp_idx] = residual_fields[2 * cmp_idx + 1];
    }
  }

  for (size_t cmp_idx = 0; cmp_idx < batch_size; ++cmp_idx) {
    const bool t = offline_data_vec[cmp_idx]->cmp_data.t;
    const Field t_share = (id_ == 0 && t) ? Field(1) : Field(0);
    const Field delta_t_share = t ? offline_data_vec[cmp_idx]->delta_share : Field(0);
    outputs[cmp_idx].gtez_share =
        t_share + gtez_prime_share[cmp_idx] -
        Field(2) * (t ? gtez_prime_share[cmp_idx] : Field(0));
    outputs[cmp_idx].delta_gtez_share =
        delta_t_share + delta_gtez_prime_share[cmp_idx] -
        Field(2) * (t ? delta_gtez_prime_share[cmp_idx] : Field(0));
  }
  return outputs;
}

EqzOfflineDataMalicious Protocol::eqz_offline_malicious(size_t lx, size_t s) {
  return eqz_offline_malicious_tagged(lx, s, 0);
}

EqzOfflineDataMalicious Protocol::eqz_offline_malicious_tagged(size_t lx, size_t s,
                                                               uint64_t domain_sep) {
  EqzOfflineDataMalicious out;
  const uint64_t base = (domain_sep << 2) | 1ULL;
  out.nonneg_data = compare_offline_malicious_internal(lx, s, false, false, base);
  out.nonpos_data = compare_offline_malicious_internal(lx, s, false, false, base + 1);
  out.domain_sep = domain_sep;
  out.ready = out.nonneg_data.ready && out.nonpos_data.ready;
  return out;
}

AuthEqzResult Protocol::eqz_online_malicious(
    const Field& x_share, const Field& delta_x_share,
    const EqzOfflineDataMalicious& offline_data) {
  AuthEqzResult out;
  if (!offline_data.ready || !offline_data.nonneg_data.ready || !offline_data.nonpos_data.ready) {
    throw std::runtime_error("eqz_online_malicious requires ready EqzOfflineDataMalicious");
  }

  const size_t lx = offline_data.nonneg_data.lx;
  const size_t s = offline_data.nonneg_data.s;
  if (lx == 0 || lx + s + 1 >= 64) {
    throw std::runtime_error("eqz_online_malicious got invalid truncation parameters");
  }
  if (offline_data.nonpos_data.lx != lx || offline_data.nonpos_data.s != s) {
    throw std::runtime_error("eqz_online_malicious requires matching truncation parameters");
  }

  if (id_ > helper_id_) {
    return out;
  }

  constexpr size_t kEqzCmpCount = 2;
  const size_t payload_len_per_cmp = lx + 2 * (lx + 2) + 1;
  const size_t total_payload_len = kEqzCmpCount * payload_len_per_cmp;

  if (id_ == helper_id_) {
    std::vector<Field> sum_cdc(kEqzCmpCount * lx, Field(0));
    std::vector<Field> sum_w(kEqzCmpCount * (lx + 2), Field(0));
    std::vector<Field> sum_delta_w(kEqzCmpCount * (lx + 2), Field(0));
    for (int p = 0; p < helper_id_; ++p) {
      std::vector<Field> recv(total_payload_len, Field(0));
      network_->recv(p, recv.data(), total_payload_len * common::utils::FIELDSIZE);
      for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
        const size_t base = cmp_idx * payload_len_per_cmp;
        const size_t cdc_base = cmp_idx * lx;
        const size_t w_base = cmp_idx * (lx + 2);
        for (size_t j = 0; j < lx; ++j) {
          sum_cdc[cdc_base + j] += recv[base + j];
        }
        for (size_t k = 0; k < lx + 2; ++k) {
          sum_w[w_base + k] += recv[base + lx + k];
          sum_delta_w[w_base + k] += recv[base + lx + (lx + 2) + k];
        }
      }
    }

    bool verdict = true;
    for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
      const size_t cdc_base = cmp_idx * lx;
      const size_t w_base = cmp_idx * (lx + 2);
      for (size_t j = 0; j < lx; ++j) {
        verdict = verdict && (sum_cdc[cdc_base + j] == Field(0));
      }
      for (size_t k = 0; k < lx + 2; ++k) {
        verdict = verdict &&
                  (helper_delta_ * sum_w[w_base + k] == sum_delta_w[w_base + k]);
      }
    }

    std::array<Field, kEqzCmpCount> gtez_prime = {Field(0), Field(0)};
    if (verdict) {
      for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
        const size_t w_base = cmp_idx * (lx + 2);
        bool any_zero = false;
        for (size_t k = 0; k < lx + 2; ++k) {
          any_zero = any_zero || (sum_w[w_base + k] == Field(0));
        }
        gtez_prime[cmp_idx] = any_zero ? Field(1) : Field(0);
      }
    }

    const Field eqz_prime =
        gtez_prime[0] + gtez_prime[1] - Field(2) * gtez_prime[0] * gtez_prime[1];
    const Field delta_eqz_prime = helper_delta_ * eqz_prime;
    Field residual_g = eqz_prime;
    Field residual_dg = delta_eqz_prime;
    for (int p = 0; p <= helper_id_ - 2; ++p) {
      auto g_prg =
          makePrgFromPairwiseKey(key_manager_.keyForParty(p), offline_data.domain_sep,
                                 PrgLabel::kEqzMalOutShare);
      auto dg_prg =
          makePrgFromPairwiseKey(key_manager_.keyForParty(p), offline_data.domain_sep,
                                 PrgLabel::kEqzMalDeltaOutShare);
      residual_g -= prgField(g_prg);
      residual_dg -= prgField(dg_prg);
    }

    const uint8_t verdict_byte = verdict ? 1 : 0;
    for (int p = 0; p < helper_id_; ++p) {
      auto* ch = network_->getSendChannel(p);
      ch->send_data(&verdict_byte, sizeof(verdict_byte));
      if (p == helper_id_ - 1 && verdict) {
        std::vector<uint8_t> residual_payload(2 * common::utils::FIELDSIZE, 0);
        NTL::BytesFromZZ(residual_payload.data(), NTL::conv<NTL::ZZ>(residual_g),
                         common::utils::FIELDSIZE);
        NTL::BytesFromZZ(residual_payload.data() + common::utils::FIELDSIZE,
                         NTL::conv<NTL::ZZ>(residual_dg), common::utils::FIELDSIZE);
        ch->send_data(residual_payload.data(), residual_payload.size());
      }
      ch->flush();
    }
    return out;
  }

  const std::array<const CompareOfflineDataMalicious*, kEqzCmpCount> off = {
      &offline_data.nonneg_data, &offline_data.nonpos_data};
  const std::array<Field, kEqzCmpCount> inputs = {x_share, -x_share};
  const std::array<Field, kEqzCmpCount> delta_inputs = {delta_x_share, -delta_x_share};

  std::array<Field, kEqzCmpCount> x_hat = {Field(0), Field(0)};
  std::array<Field, kEqzCmpCount> delta_x_hat = {Field(0), Field(0)};
  std::array<Field, kEqzCmpCount> u_star = {Field(0), Field(0)};
  std::array<Field, kEqzCmpCount> delta_u_star = {Field(0), Field(0)};
  const Field one_share = (id_ == 0) ? Field(1) : Field(0);

  std::vector<Field> c_local(kEqzCmpCount * lx, Field(0));
  std::vector<Field> delta_c_local(kEqzCmpCount * lx, Field(0));
  for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
    const Field sign = (off[cmp_idx]->cmp_data.t) ? Field(-1) : Field(1);
    x_hat[cmp_idx] = inputs[cmp_idx] * sign;
    delta_x_hat[cmp_idx] = delta_inputs[cmp_idx] * sign;
    u_star[cmp_idx] = one_share * sign;
    delta_u_star[cmp_idx] = off[cmp_idx]->delta_share * sign;
    const Field shift_field = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(lx - 1)));
    const Field z_i = x_hat[cmp_idx] + one_share * shift_field;
    const Field delta_z_i = delta_x_hat[cmp_idx] + off[cmp_idx]->delta_share * shift_field;
    for (size_t j = 1; j <= lx; ++j) {
      const Field two_pow_j = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(j)));
      c_local[cmp_idx * lx + (j - 1)] =
          z_i + two_pow_j * off[cmp_idx]->r_share[j - 1] + off[cmp_idx]->r0_share[j - 1];
      delta_c_local[cmp_idx * lx + (j - 1)] =
          delta_z_i + two_pow_j * off[cmp_idx]->delta_r_share[j - 1] +
          off[cmp_idx]->delta_r0_share[j - 1];
    }
  }

  const auto c_open = openVectorToComputingParties(c_local);
  if (c_open.size() != kEqzCmpCount * lx) {
    throw std::runtime_error("eqz_online_malicious opening size mismatch");
  }

  std::array<std::vector<Field>, kEqzCmpCount> c_dc = {
      std::vector<Field>(lx, Field(0)), std::vector<Field>(lx, Field(0))};
  std::array<std::vector<Field>, kEqzCmpCount> w = {
      std::vector<Field>(lx + 2, Field(0)), std::vector<Field>(lx + 2, Field(0))};
  std::array<std::vector<Field>, kEqzCmpCount> delta_w = {
      std::vector<Field>(lx + 2, Field(0)), std::vector<Field>(lx + 2, Field(0))};
  for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
    std::vector<Field> u(lx + 1, Field(0));
    std::vector<Field> delta_u(lx + 1, Field(0));
    u[0] = x_hat[cmp_idx];
    delta_u[0] = delta_x_hat[cmp_idx];
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t two_pow_j = pow2Bound(j);
      const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
      const uint64_t c_u64 =
          NTL::conv<uint64_t>(NTL::rep(c_open[cmp_idx * lx + (j - 1)]));
      const Field c0_field = NTL::conv<Field>(NTL::to_ZZ(c_u64 & (two_pow_j - 1)));
      const Field d_i = one_share * c0_field - off[cmp_idx]->r0_share[j - 1];
      const Field delta_d_i =
          off[cmp_idx]->delta_share * c0_field - off[cmp_idx]->delta_r0_share[j - 1];
      u[j] = inv2pow * (x_hat[cmp_idx] - d_i);
      delta_u[j] = inv2pow * (delta_x_hat[cmp_idx] - delta_d_i);
      c_dc[cmp_idx][j - 1] =
          off[cmp_idx]->delta_share * c_open[cmp_idx * lx + (j - 1)] -
          delta_c_local[cmp_idx * lx + (j - 1)];
    }

    Field v_star = u_star[cmp_idx] + Field(3) * u[0] - one_share;
    Field delta_v_star = delta_u_star[cmp_idx] + Field(3) * delta_u[0] - off[cmp_idx]->delta_share;
    std::vector<Field> w_tmp(lx + 2, Field(0));
    std::vector<Field> delta_w_tmp(lx + 2, Field(0));
    w_tmp[0] = off[cmp_idx]->cmp_data.rho[0] * v_star;
    delta_w_tmp[0] = off[cmp_idx]->cmp_data.rho[0] * delta_v_star;
    for (size_t j = 0; j <= lx; ++j) {
      Field sum = Field(0);
      Field delta_sum = Field(0);
      for (size_t k = j; k <= lx; ++k) {
        sum += u[k];
        delta_sum += delta_u[k];
      }
      w_tmp[j + 1] = off[cmp_idx]->cmp_data.rho[j + 1] * (sum - one_share);
      delta_w_tmp[j + 1] =
          off[cmp_idx]->cmp_data.rho[j + 1] * (delta_sum - off[cmp_idx]->delta_share);
    }
    for (size_t i = 0; i < w_tmp.size(); ++i) {
      const size_t pos = off[cmp_idx]->cmp_data.permutation[i];
      w[cmp_idx][i] = w_tmp[pos];
      delta_w[cmp_idx][i] = delta_w_tmp[pos];
    }
  }

  std::vector<Field> payload;
  payload.reserve(total_payload_len);
  for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
    payload.insert(payload.end(), c_dc[cmp_idx].begin(), c_dc[cmp_idx].end());
    payload.insert(payload.end(), w[cmp_idx].begin(), w[cmp_idx].end());
    payload.insert(payload.end(), delta_w[cmp_idx].begin(), delta_w[cmp_idx].end());
    payload.push_back(x_hat[cmp_idx]);
  }
  auto bytes = serializeFieldVector(payload);
  auto* channel = network_->getSendChannel(helper_id_);
  channel->send_data(bytes.data(), bytes.size());
  channel->flush();

  uint8_t verdict = 0;
  network_->recv(helper_id_, &verdict, sizeof(verdict));
  if (verdict == 0) {
    throw std::runtime_error("eqz_online_malicious aborted by helper");
  }

  Field eqz_prime_share = Field(0);
  Field delta_eqz_prime_share = Field(0);
  if (id_ <= helper_id_ - 2) {
      auto g_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(), offline_data.domain_sep,
                                          PrgLabel::kEqzMalOutShare);
      auto dg_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(),
                                           offline_data.domain_sep,
                                           PrgLabel::kEqzMalDeltaOutShare);
    eqz_prime_share = prgField(g_prg);
    delta_eqz_prime_share = prgField(dg_prg);
  } else {
    std::vector<uint8_t> residual_payload(2 * common::utils::FIELDSIZE, 0);
    network_->recv(helper_id_, residual_payload.data(), residual_payload.size());
    eqz_prime_share =
        NTL::conv<Field>(NTL::ZZFromBytes(residual_payload.data(), common::utils::FIELDSIZE));
    delta_eqz_prime_share = NTL::conv<Field>(
        NTL::ZZFromBytes(residual_payload.data() + common::utils::FIELDSIZE,
                         common::utils::FIELDSIZE));
  }

  const bool tprime = off[0]->cmp_data.t ^ off[1]->cmp_data.t;
  if (tprime) {
    out.eqz_share = eqz_prime_share;
    out.delta_eqz_share = delta_eqz_prime_share;
  } else {
    out.eqz_share = one_share - eqz_prime_share;
    out.delta_eqz_share = off[0]->delta_share - delta_eqz_prime_share;
  }
  return out;
}

std::vector<AuthEqzResult> Protocol::eqz_online_malicious_batch(
    const std::vector<Field>& x_shares, const std::vector<Field>& delta_x_shares,
    const std::vector<const EqzOfflineDataMalicious*>& offline_data_vec) {
  if (x_shares.size() != delta_x_shares.size() || x_shares.size() != offline_data_vec.size()) {
    throw std::runtime_error("eqz_online_malicious_batch input size mismatch");
  }
  std::vector<AuthEqzResult> outputs(x_shares.size());
  if (x_shares.empty()) {
    return outputs;
  }

  size_t lx = 0;
  size_t s = 0;
  for (size_t i = 0; i < offline_data_vec.size(); ++i) {
    const auto* offline_data = offline_data_vec[i];
    if (offline_data == nullptr || !offline_data->ready || !offline_data->nonneg_data.ready ||
        !offline_data->nonpos_data.ready) {
      throw std::runtime_error("eqz_online_malicious_batch requires ready EqzOfflineDataMalicious");
    }
    if (i == 0) {
      lx = offline_data->nonneg_data.lx;
      s = offline_data->nonneg_data.s;
      if (lx == 0 || lx + s + 1 >= 64) {
        throw std::runtime_error("eqz_online_malicious_batch got invalid truncation parameters");
      }
    }
    if (offline_data->nonneg_data.lx != lx || offline_data->nonneg_data.s != s ||
        offline_data->nonpos_data.lx != lx || offline_data->nonpos_data.s != s) {
      throw std::runtime_error(
          "eqz_online_malicious_batch requires matching truncation parameters");
    }
  }

  if (id_ > helper_id_) {
    return outputs;
  }

  constexpr size_t kEqzCmpCount = 2;
  const size_t batch_size = x_shares.size();
  const size_t payload_len_per_cmp = lx + 2 * (lx + 2) + 1;
  const size_t total_payload_len = batch_size * kEqzCmpCount * payload_len_per_cmp;

  if (id_ == helper_id_) {
    std::vector<Field> sum_payload(total_payload_len, Field(0));
    for (int p = 0; p < helper_id_; ++p) {
      std::vector<Field> recv(total_payload_len, Field(0));
      network_->recv(p, recv.data(), total_payload_len * common::utils::FIELDSIZE);
      for (size_t i = 0; i < total_payload_len; ++i) {
        sum_payload[i] += recv[i];
      }
    }

    bool verdict = true;
    for (size_t eqz_idx = 0; eqz_idx < batch_size && verdict; ++eqz_idx) {
      for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount && verdict; ++cmp_idx) {
        const size_t base = (eqz_idx * kEqzCmpCount + cmp_idx) * payload_len_per_cmp;
        for (size_t j = 0; j < lx; ++j) {
          verdict = verdict && (sum_payload[base + j] == Field(0));
        }
        for (size_t k = 0; k < lx + 2; ++k) {
          verdict = verdict &&
                    (helper_delta_ * sum_payload[base + lx + k] ==
                     sum_payload[base + lx + (lx + 2) + k]);
        }
      }
    }

    std::vector<Field> residual_g(batch_size, Field(0));
    std::vector<Field> residual_dg(batch_size, Field(0));
    if (verdict) {
      for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
        std::array<Field, kEqzCmpCount> gtez_prime = {Field(0), Field(0)};
        for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
          const size_t base = (eqz_idx * kEqzCmpCount + cmp_idx) * payload_len_per_cmp;
          bool any_zero = false;
          for (size_t k = 0; k < lx + 2; ++k) {
            any_zero = any_zero || (sum_payload[base + lx + k] == Field(0));
          }
          gtez_prime[cmp_idx] = any_zero ? Field(1) : Field(0);
        }

        const Field eqz_prime =
            gtez_prime[0] + gtez_prime[1] - Field(2) * gtez_prime[0] * gtez_prime[1];
        const Field delta_eqz_prime = helper_delta_ * eqz_prime;
        residual_g[eqz_idx] = eqz_prime;
        residual_dg[eqz_idx] = delta_eqz_prime;
        for (int p = 0; p <= helper_id_ - 2; ++p) {
          auto g_prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p),
                                              offline_data_vec[eqz_idx]->domain_sep,
                                              PrgLabel::kEqzMalOutShare);
          auto dg_prg = makePrgFromPairwiseKey(key_manager_.keyForParty(p),
                                               offline_data_vec[eqz_idx]->domain_sep,
                                               PrgLabel::kEqzMalDeltaOutShare);
          residual_g[eqz_idx] -= prgField(g_prg);
          residual_dg[eqz_idx] -= prgField(dg_prg);
        }
      }
    }

    const uint8_t verdict_byte = verdict ? 1 : 0;
    for (int p = 0; p < helper_id_; ++p) {
      auto* ch = network_->getSendChannel(p);
      ch->send_data(&verdict_byte, sizeof(verdict_byte));
      if (p == helper_id_ - 1 && verdict) {
        std::vector<Field> residual_payload;
        residual_payload.reserve(2 * batch_size);
        for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
          residual_payload.push_back(residual_g[eqz_idx]);
          residual_payload.push_back(residual_dg[eqz_idx]);
        }
        auto bytes = serializeFieldVector(residual_payload);
        ch->send_data(bytes.data(), bytes.size());
      }
      ch->flush();
    }
    return outputs;
  }

  const Field one_share = (id_ == 0) ? Field(1) : Field(0);
  std::vector<Field> c_local(batch_size * kEqzCmpCount * lx, Field(0));
  std::vector<Field> delta_c_local(batch_size * kEqzCmpCount * lx, Field(0));
  for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
    const std::array<const CompareOfflineDataMalicious*, kEqzCmpCount> off = {
        &offline_data_vec[eqz_idx]->nonneg_data, &offline_data_vec[eqz_idx]->nonpos_data};
    const std::array<Field, kEqzCmpCount> inputs = {x_shares[eqz_idx], -x_shares[eqz_idx]};
    const std::array<Field, kEqzCmpCount> delta_inputs = {delta_x_shares[eqz_idx],
                                                          -delta_x_shares[eqz_idx]};

    for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
      const Field sign = off[cmp_idx]->cmp_data.t ? Field(-1) : Field(1);
      const Field x_hat = inputs[cmp_idx] * sign;
      const Field delta_x_hat = delta_inputs[cmp_idx] * sign;
      const Field shift_field = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(lx - 1)));
      const Field z_i = x_hat + one_share * shift_field;
      const Field delta_z_i = delta_x_hat + off[cmp_idx]->delta_share * shift_field;
      for (size_t j = 1; j <= lx; ++j) {
        const Field two_pow_j = NTL::conv<Field>(NTL::to_ZZ(pow2Bound(j)));
        c_local[(eqz_idx * kEqzCmpCount + cmp_idx) * lx + (j - 1)] =
            z_i + two_pow_j * off[cmp_idx]->r_share[j - 1] + off[cmp_idx]->r0_share[j - 1];
        delta_c_local[(eqz_idx * kEqzCmpCount + cmp_idx) * lx + (j - 1)] =
            delta_z_i + two_pow_j * off[cmp_idx]->delta_r_share[j - 1] +
            off[cmp_idx]->delta_r0_share[j - 1];
      }
    }
  }

  const auto c_open = openVectorToComputingParties(c_local);
  if (c_open.size() != c_local.size()) {
    throw std::runtime_error("eqz_online_malicious_batch opening size mismatch");
  }

  std::vector<Field> payload;
  payload.reserve(total_payload_len);
  for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
    const std::array<const CompareOfflineDataMalicious*, kEqzCmpCount> off = {
        &offline_data_vec[eqz_idx]->nonneg_data, &offline_data_vec[eqz_idx]->nonpos_data};
    const std::array<Field, kEqzCmpCount> inputs = {x_shares[eqz_idx], -x_shares[eqz_idx]};
    const std::array<Field, kEqzCmpCount> delta_inputs = {delta_x_shares[eqz_idx],
                                                          -delta_x_shares[eqz_idx]};

    for (size_t cmp_idx = 0; cmp_idx < kEqzCmpCount; ++cmp_idx) {
      const Field sign = off[cmp_idx]->cmp_data.t ? Field(-1) : Field(1);
      const Field x_hat = inputs[cmp_idx] * sign;
      const Field delta_x_hat = delta_inputs[cmp_idx] * sign;
      const Field u_star = one_share * sign;
      const Field delta_u_star = off[cmp_idx]->delta_share * sign;

      std::vector<Field> u(lx + 1, Field(0));
      std::vector<Field> delta_u(lx + 1, Field(0));
      std::vector<Field> c_dc(lx, Field(0));
      u[0] = x_hat;
      delta_u[0] = delta_x_hat;
      for (size_t j = 1; j <= lx; ++j) {
        const uint64_t two_pow_j = pow2Bound(j);
        const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
        const uint64_t c_u64 = NTL::conv<uint64_t>(
            NTL::rep(c_open[(eqz_idx * kEqzCmpCount + cmp_idx) * lx + (j - 1)]));
        const Field c0_field = NTL::conv<Field>(NTL::to_ZZ(c_u64 & (two_pow_j - 1)));
        const Field d_i = one_share * c0_field - off[cmp_idx]->r0_share[j - 1];
        const Field delta_d_i =
            off[cmp_idx]->delta_share * c0_field - off[cmp_idx]->delta_r0_share[j - 1];
        u[j] = inv2pow * (x_hat - d_i);
        delta_u[j] = inv2pow * (delta_x_hat - delta_d_i);
        c_dc[j - 1] = off[cmp_idx]->delta_share *
                          c_open[(eqz_idx * kEqzCmpCount + cmp_idx) * lx + (j - 1)] -
                      delta_c_local[(eqz_idx * kEqzCmpCount + cmp_idx) * lx + (j - 1)];
      }

      const Field v_star = u_star + Field(3) * u[0] - one_share;
      const Field delta_v_star = delta_u_star + Field(3) * delta_u[0] - off[cmp_idx]->delta_share;
      std::vector<Field> w_tmp(lx + 2, Field(0));
      std::vector<Field> delta_w_tmp(lx + 2, Field(0));
      w_tmp[0] = off[cmp_idx]->cmp_data.rho[0] * v_star;
      delta_w_tmp[0] = off[cmp_idx]->cmp_data.rho[0] * delta_v_star;
      for (size_t j = 0; j <= lx; ++j) {
        Field sum = Field(0);
        Field delta_sum = Field(0);
        for (size_t k = j; k <= lx; ++k) {
          sum += u[k];
          delta_sum += delta_u[k];
        }
        w_tmp[j + 1] = off[cmp_idx]->cmp_data.rho[j + 1] * (sum - one_share);
        delta_w_tmp[j + 1] =
            off[cmp_idx]->cmp_data.rho[j + 1] * (delta_sum - off[cmp_idx]->delta_share);
      }

      std::vector<Field> w(lx + 2, Field(0));
      std::vector<Field> delta_w(lx + 2, Field(0));
      for (size_t i = 0; i < w_tmp.size(); ++i) {
        const size_t pos = off[cmp_idx]->cmp_data.permutation[i];
        w[i] = w_tmp[pos];
        delta_w[i] = delta_w_tmp[pos];
      }

      payload.insert(payload.end(), c_dc.begin(), c_dc.end());
      payload.insert(payload.end(), w.begin(), w.end());
      payload.insert(payload.end(), delta_w.begin(), delta_w.end());
      payload.push_back(x_hat);
    }
  }

  auto bytes = serializeFieldVector(payload);
  auto* channel = network_->getSendChannel(helper_id_);
  channel->send_data(bytes.data(), bytes.size());
  channel->flush();

  uint8_t verdict = 0;
  network_->recv(helper_id_, &verdict, sizeof(verdict));
  if (verdict == 0) {
    throw std::runtime_error("eqz_online_malicious_batch aborted by helper");
  }

  std::vector<Field> eqz_prime_share(batch_size, Field(0));
  std::vector<Field> delta_eqz_prime_share(batch_size, Field(0));
  if (id_ <= helper_id_ - 2) {
    for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
      auto g_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(),
                                          offline_data_vec[eqz_idx]->domain_sep,
                                          PrgLabel::kEqzMalOutShare);
      auto dg_prg = makePrgFromPairwiseKey(key_manager_.keyWithHelper(),
                                           offline_data_vec[eqz_idx]->domain_sep,
                                           PrgLabel::kEqzMalDeltaOutShare);
      eqz_prime_share[eqz_idx] = prgField(g_prg);
      delta_eqz_prime_share[eqz_idx] = prgField(dg_prg);
    }
  } else {
    std::vector<uint8_t> residual_payload(2 * batch_size * common::utils::FIELDSIZE, 0);
    network_->recv(helper_id_, residual_payload.data(), residual_payload.size());
    const auto residual_fields = deserializeFieldVector(residual_payload);
    if (residual_fields.size() != 2 * batch_size) {
      throw std::runtime_error("eqz_online_malicious_batch residual size mismatch");
    }
    for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
      eqz_prime_share[eqz_idx] = residual_fields[2 * eqz_idx];
      delta_eqz_prime_share[eqz_idx] = residual_fields[2 * eqz_idx + 1];
    }
  }

  for (size_t eqz_idx = 0; eqz_idx < batch_size; ++eqz_idx) {
    const bool tprime = offline_data_vec[eqz_idx]->nonneg_data.cmp_data.t ^
                        offline_data_vec[eqz_idx]->nonpos_data.cmp_data.t;
    if (tprime) {
      outputs[eqz_idx].eqz_share = eqz_prime_share[eqz_idx];
      outputs[eqz_idx].delta_eqz_share = delta_eqz_prime_share[eqz_idx];
    } else {
      outputs[eqz_idx].eqz_share = one_share - eqz_prime_share[eqz_idx];
      outputs[eqz_idx].delta_eqz_share =
          offline_data_vec[eqz_idx]->nonneg_data.delta_share - delta_eqz_prime_share[eqz_idx];
    }
  }
  return outputs;
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

std::vector<Field> Protocol::onlineSemiHonestForBenchmark(
    const std::unordered_map<wire_t, Field>& inputs,
    const std::vector<TripleShare>& triples) {
  MulOfflineData off;
  off.triples = triples;
  off.ready = true;
  return mul_online_semi_honest(inputs, off);
}

std::vector<Field> Protocol::probabilisticTruncate(const std::vector<Field>& x_shares, size_t ell_x,
                                                   size_t m, size_t s) {
  auto off = trunc_offline(x_shares.size(), ell_x, m, s);
  return trunc_online(x_shares, off);
}

Field Protocol::openToComputingParties(const Field& local_share) const {
  if (id_ >= helper_id_) {
    return Field(0);
  }

  const auto peers = computingPeerIdsExcludingSelf();
  std::vector<Field> local_vec = {local_share};
  // Full-duplex model: this open is one round (send+recv overlap).
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
  // Full-duplex model: this batched open is one round (send+recv overlap).
  const auto network_phase_start = std::chrono::steady_clock::now();
  sendFieldVectorToPeers(peers, local_vec);

  auto recv_all = recvFieldVectorsFromPeers(peers, local_vec.size());
  const auto network_phase_end = std::chrono::steady_clock::now();
  auto* self = const_cast<Protocol*>(this);
  self->online_timing_stats_.network_overhead_ms +=
      std::chrono::duration<double, std::milli>(network_phase_end - network_phase_start).count();
  self->online_timing_stats_.ready = true;
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

}  // namespace asterisk2
