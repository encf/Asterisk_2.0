#include "protocol.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>
#include <thread>

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

std::mt19937_64 helperTruncRng(int seed, size_t idx) {
  return std::mt19937_64(static_cast<uint64_t>(seed) * 104729ULL + idx);
}

uint64_t pow2Bound(size_t bits) {
  if (bits >= 64) {
    throw std::runtime_error("pow2Bound supports bit lengths < 64");
  }
  return (1ULL << bits);
}

Field randomFieldBounded(std::mt19937_64& rng, uint64_t bound) {
  if (bound == 0) {
    return Field(0);
  }
  return NTL::conv<Field>(NTL::to_ZZ(static_cast<unsigned long>(rng() % bound)));
}
}  // namespace

Protocol::Protocol(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                   LevelOrderedCircuit circ, int seed, ProtocolConfig config)
    : nP_(nP),
      id_(id),
      helper_id_(nP),
      seed_(seed),
      config_(config),
      network_(std::move(network)),
      circ_(std::move(circ)),
      wire_share_(circ_.num_gates, Field(0)) {}

std::vector<TripleShare> Protocol::offline() {
  if (config_.security_model == SecurityModel::kMalicious) {
    throw std::runtime_error(
        "Asterisk2.0 malicious model is not implemented yet; use semi-honest mode");
  }

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
      constexpr size_t kTripleElements = 3;
      maybeSimulateStep(kTripleElements * common::utils::FIELDSIZE);
      network_->send(nP_ - 1, pack, kTripleElements * common::utils::FIELDSIZE);
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
      constexpr size_t kTripleElements = 3;
      maybeSimulateStep(kTripleElements * common::utils::FIELDSIZE);
      network_->recv(helper_id_, pack, kTripleElements * common::utils::FIELDSIZE);
      triples[g].a = pack[0];
      triples[g].b = pack[1];
      triples[g].c = pack[2];
    }
  }

  return triples;
}

std::vector<Protocol::OpenPair> Protocol::openPairsToComputingParties(
    const std::vector<OpenPair>& local_pairs) const {
  if (id_ >= helper_id_) {
    return {};
  }

  const size_t gates = local_pairs.size();
  std::vector<Field> send_buf(gates * 2);
  for (size_t i = 0; i < gates; ++i) {
    send_buf[2 * i] = local_pairs[i].d;
    send_buf[2 * i + 1] = local_pairs[i].e;
  }

  const size_t peers = static_cast<size_t>(helper_id_ - 1);
  maybeSimulateStep(send_buf.size() * common::utils::FIELDSIZE * peers);
  const bool use_parallel_io = config_.parallel_send && peers >= 3 && gates >= 64;
  if (use_parallel_io) {
    const size_t serialized_bytes = send_buf.size() * common::utils::FIELDSIZE;
    std::vector<uint8_t> send_serialized(serialized_bytes);
    for (size_t i = 0; i < send_buf.size(); ++i) {
      NTL::BytesFromZZ(send_serialized.data() + i * common::utils::FIELDSIZE,
                       NTL::conv<NTL::ZZ>(send_buf[i]), common::utils::FIELDSIZE);
    }

    std::vector<int> peer_ids;
    peer_ids.reserve(peers);
    for (int p = 0; p < helper_id_; ++p) {
      if (p != id_) {
        peer_ids.push_back(p);
      }
    }

    std::vector<std::thread> send_threads;
    send_threads.reserve(peer_ids.size());
    for (int peer : peer_ids) {
      send_threads.emplace_back([&, peer]() {
        auto* channel = network_->getSendChannel(peer);
        channel->send_data(send_serialized.data(), send_serialized.size());
        channel->flush();
      });
    }
    for (auto& th : send_threads) {
      th.join();
    }

    std::vector<OpenPair> sums = local_pairs;
    maybeSimulateStep(send_buf.size() * common::utils::FIELDSIZE * peers);

    std::vector<std::vector<uint8_t>> recv_serialized(
        peer_ids.size(), std::vector<uint8_t>(serialized_bytes));
    std::vector<std::thread> recv_threads;
    recv_threads.reserve(peer_ids.size());
    for (size_t idx = 0; idx < peer_ids.size(); ++idx) {
      recv_threads.emplace_back([&, idx]() {
        auto* channel = network_->getRecvChannel(peer_ids[idx]);
        channel->recv_data(recv_serialized[idx].data(), recv_serialized[idx].size());
      });
    }
    for (auto& th : recv_threads) {
      th.join();
    }

    for (const auto& peer_buf : recv_serialized) {
      for (size_t i = 0; i < gates; ++i) {
        const auto d = NTL::ZZFromBytes(peer_buf.data() + (2 * i) * common::utils::FIELDSIZE,
                                        common::utils::FIELDSIZE);
        const auto e = NTL::ZZFromBytes(peer_buf.data() + (2 * i + 1) * common::utils::FIELDSIZE,
                                        common::utils::FIELDSIZE);
        sums[i].d += NTL::conv<Field>(d);
        sums[i].e += NTL::conv<Field>(e);
      }
    }

    return sums;
  } else {
    for (int p = 0; p < helper_id_; ++p) {
      if (p != id_) {
        network_->send(p, send_buf.data(), send_buf.size() * common::utils::FIELDSIZE);
      }
    }
    network_->flush();

    std::vector<OpenPair> sums = local_pairs;
    std::vector<Field> recv_buf(gates * 2);
    maybeSimulateStep(recv_buf.size() * common::utils::FIELDSIZE * peers);
    for (int p = 0; p < helper_id_; ++p) {
      if (p == id_) {
        continue;
      }
      network_->recv(p, recv_buf.data(), recv_buf.size() * common::utils::FIELDSIZE);
      for (size_t i = 0; i < gates; ++i) {
        sums[i].d += recv_buf[2 * i];
        sums[i].e += recv_buf[2 * i + 1];
      }
    }

    return sums;
  }
}

Field Protocol::openToComputingParties(const Field& local_share) const {
  if (id_ >= helper_id_) {
    return Field(0);
  }

  maybeSimulateStep(common::utils::FIELDSIZE * static_cast<size_t>(helper_id_ - 1));
  for (int p = 0; p < helper_id_; ++p) {
    if (p != id_) {
      network_->send(p, &local_share, common::utils::FIELDSIZE);
    }
  }
  network_->flush();

  Field opened = local_share;
  Field recv_val = Field(0);
  maybeSimulateStep(common::utils::FIELDSIZE * static_cast<size_t>(helper_id_ - 1));
  for (int p = 0; p < helper_id_; ++p) {
    if (p == id_) {
      continue;
    }
    network_->recv(p, &recv_val, common::utils::FIELDSIZE);
    opened += recv_val;
  }
  return opened;
}

std::vector<Field> Protocol::openVectorToComputingParties(
    const std::vector<Field>& local_vec) const {
  if (id_ >= helper_id_) {
    return {};
  }
  const size_t len = local_vec.size();
  std::vector<Field> opened = local_vec;
  if (len == 0) {
    return opened;
  }
  const size_t bytes = len * common::utils::FIELDSIZE;
  maybeSimulateStep(bytes * static_cast<size_t>(helper_id_ - 1));
  for (int p = 0; p < helper_id_; ++p) {
    if (p != id_) {
      network_->send(p, local_vec.data(), bytes);
    }
  }
  network_->flush();

  std::vector<Field> recv_buf(len, Field(0));
  maybeSimulateStep(bytes * static_cast<size_t>(helper_id_ - 1));
  for (int p = 0; p < helper_id_; ++p) {
    if (p == id_) {
      continue;
    }
    network_->recv(p, recv_buf.data(), bytes);
    for (size_t i = 0; i < len; ++i) {
      opened[i] += recv_buf[i];
    }
  }
  return opened;
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
  // seconds = bits / (megabits_per_sec * 1e6)
  const double bits = static_cast<double>(bytes) * 8.0;
  const double seconds = bits / (config_.sim_bandwidth_mbps * 1e6);
  if (seconds > 0) {
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
  }
}

std::vector<Field> Protocol::online(
    const std::unordered_map<wire_t, Field>& inputs,
    const std::vector<TripleShare>& triples) {
  if (config_.security_model == SecurityModel::kMalicious) {
    throw std::runtime_error(
        "Asterisk2.0 malicious model is not implemented yet; use semi-honest mode");
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
        if (mul_idx + i >= triples.size()) {
          throw std::runtime_error("Insufficient Beaver triples in online phase");
        }
        const auto* g = mul_gates[i];
        const auto& t = triples[mul_idx + i];
        local_pairs[i].d = wire_share_[g->in1] - t.a;
        local_pairs[i].e = wire_share_[g->in2] - t.b;
      }

      auto opened = openPairsToComputingParties(local_pairs);
      for (size_t i = 0; i < mul_gates.size(); ++i) {
        const auto* g = mul_gates[i];
        const auto& t = triples[mul_idx + i];
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

std::vector<Field> Protocol::probabilisticTruncate(
    const std::vector<Field>& x_shares, size_t ell_x, size_t m, size_t s) {
  if (id_ > helper_id_) {
    return {};
  }
  if (m == 0 || m > ell_x) {
    throw std::runtime_error("probabilisticTruncate requires 0 < m <= ell_x");
  }
  if (ell_x + s + 1 >= 64) {
    throw std::runtime_error("probabilisticTruncate requires ell_x + s + 1 < 64");
  }
  const uint64_t bound_r = pow2Bound(ell_x - m + s);
  const uint64_t bound_r0 = pow2Bound(m);
  const uint64_t two_pow_m = pow2Bound(m);
  const uint64_t two_pow_lx_minus_1 = pow2Bound(ell_x - 1);
  const Field lambda_m = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_m)));

  std::vector<Field> out(x_shares.size(), Field(0));
  if (id_ == helper_id_) {
    for (size_t idx = 0; idx < x_shares.size(); ++idx) {
      auto hrg = helperTruncRng(seed_, idx);
      Field r = randomFieldBounded(hrg, bound_r);
      Field r0 = randomFieldBounded(hrg, bound_r0);
      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto prg = partyHelperRng(seed_ + 17, i, idx);
        auto ri = randomFieldBounded(prg, bound_r);
        auto r0i = randomFieldBounded(prg, bound_r0);
        sum_r += ri;
        sum_r0 += r0i;
      }
      Field pack[2] = {r - sum_r, r0 - sum_r0};
      maybeSimulateStep(2 * common::utils::FIELDSIZE);
      network_->send(nP_ - 1, pack, 2 * common::utils::FIELDSIZE);
    }
    network_->flush();
    return out;
  }

  std::vector<Field> r_share(x_shares.size(), Field(0));
  std::vector<Field> r0_share(x_shares.size(), Field(0));
  if (id_ <= nP_ - 2) {
    for (size_t idx = 0; idx < x_shares.size(); ++idx) {
      auto prg = partyHelperRng(seed_ + 17, id_, idx);
      r_share[idx] = randomFieldBounded(prg, bound_r);
      r0_share[idx] = randomFieldBounded(prg, bound_r0);
    }
  } else if (id_ == nP_ - 1) {
    for (size_t idx = 0; idx < x_shares.size(); ++idx) {
      Field pack[2];
      maybeSimulateStep(2 * common::utils::FIELDSIZE);
      network_->recv(helper_id_, pack, 2 * common::utils::FIELDSIZE);
      r_share[idx] = pack[0];
      r0_share[idx] = pack[1];
    }
  }

  for (size_t idx = 0; idx < x_shares.size(); ++idx) {
    Field z_i = x_shares[idx] + ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1))
                                            : Field(0));
    Field c_i = z_i + NTL::conv<Field>(NTL::to_ZZ(two_pow_m)) * r_share[idx] + r0_share[idx];
    Field c = openToComputingParties(c_i);
    uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c));
    uint64_t c0 = c_u64 & (two_pow_m - 1);
    Field d_i = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) - r0_share[idx];
    out[idx] = lambda_m * (x_shares[idx] - d_i);
  }
  return out;
}

std::vector<Field> Protocol::batchedTruncateAll(const Field& x_share, size_t lx,
                                                size_t s, BGTEZStats* stats) {
  if (lx == 0) {
    throw std::runtime_error("batchedTruncateAll requires lx > 0");
  }
  if (lx + s + 1 >= 64) {
    throw std::runtime_error("batchedTruncateAll requires lx + s + 1 < 64");
  }
  if (id_ > helper_id_) {
    return {};
  }

  std::vector<Field> r_share(lx, Field(0));
  std::vector<Field> r0_share(lx, Field(0));
  if (id_ == helper_id_) {
    std::vector<Field> pack(2 * lx, Field(0));
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto hrg = helperTruncRng(seed_ + 31000, j);
      Field r = randomFieldBounded(hrg, bound_r);
      Field r0 = randomFieldBounded(hrg, bound_r0);
      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto prg = partyHelperRng(seed_ + 32000, i, j);
        auto ri = randomFieldBounded(prg, bound_r);
        auto r0i = randomFieldBounded(prg, bound_r0);
        sum_r += ri;
        sum_r0 += r0i;
      }
      pack[2 * (j - 1)] = r - sum_r;
      pack[2 * (j - 1) + 1] = r0 - sum_r0;
    }
    maybeSimulateStep(pack.size() * common::utils::FIELDSIZE);
    network_->send(nP_ - 1, pack.data(), pack.size() * common::utils::FIELDSIZE);
    network_->flush();
    return {};
  }

  if (id_ <= nP_ - 2) {
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto prg = partyHelperRng(seed_ + 32000, id_, j);
      r_share[j - 1] = randomFieldBounded(prg, bound_r);
      r0_share[j - 1] = randomFieldBounded(prg, bound_r0);
    }
  } else if (id_ == nP_ - 1) {
    std::vector<Field> pack(2 * lx, Field(0));
    maybeSimulateStep(pack.size() * common::utils::FIELDSIZE);
    network_->recv(helper_id_, pack.data(), pack.size() * common::utils::FIELDSIZE);
    for (size_t j = 0; j < lx; ++j) {
      r_share[j] = pack[2 * j];
      r0_share[j] = pack[2 * j + 1];
    }
  }

  std::vector<Field> c_local(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
    Field z = x_share + ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
    c_local[j - 1] =
        z + NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) * r_share[j - 1] + r0_share[j - 1];
  }
  auto c_open = openVectorToComputingParties(c_local);
  if (stats != nullptr) {
    stats->batched_open_calls += 1;
  }
  if (c_open.size() != lx) {
    throw std::runtime_error("batchedTruncateAll reconstructed vector size mismatch");
  }

  std::vector<Field> u(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c_open[j - 1]));
    const uint64_t c0 = c_u64 & (two_pow_j - 1);
    Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) - r0_share[j - 1];
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
  if (lx + s + 1 >= 64) {
    throw std::runtime_error("serialTruncateAllForTesting requires lx + s + 1 < 64");
  }
  if (id_ > helper_id_) {
    return {};
  }

  std::vector<Field> r_share(lx, Field(0));
  std::vector<Field> r0_share(lx, Field(0));
  if (id_ == helper_id_) {
    std::vector<Field> pack(2 * lx, Field(0));
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto hrg = helperTruncRng(seed_ + 31000, j);
      Field r = randomFieldBounded(hrg, bound_r);
      Field r0 = randomFieldBounded(hrg, bound_r0);
      Field sum_r = Field(0);
      Field sum_r0 = Field(0);
      for (int i = 0; i <= nP_ - 2; ++i) {
        auto prg = partyHelperRng(seed_ + 32000, i, j);
        auto ri = randomFieldBounded(prg, bound_r);
        auto r0i = randomFieldBounded(prg, bound_r0);
        sum_r += ri;
        sum_r0 += r0i;
      }
      pack[2 * (j - 1)] = r - sum_r;
      pack[2 * (j - 1) + 1] = r0 - sum_r0;
    }
    maybeSimulateStep(pack.size() * common::utils::FIELDSIZE);
    network_->send(nP_ - 1, pack.data(), pack.size() * common::utils::FIELDSIZE);
    network_->flush();
    return {};
  }

  if (id_ <= nP_ - 2) {
    for (size_t j = 1; j <= lx; ++j) {
      const uint64_t bound_r = pow2Bound(lx - j + s);
      const uint64_t bound_r0 = pow2Bound(j);
      auto prg = partyHelperRng(seed_ + 32000, id_, j);
      r_share[j - 1] = randomFieldBounded(prg, bound_r);
      r0_share[j - 1] = randomFieldBounded(prg, bound_r0);
    }
  } else if (id_ == nP_ - 1) {
    std::vector<Field> pack(2 * lx, Field(0));
    maybeSimulateStep(pack.size() * common::utils::FIELDSIZE);
    network_->recv(helper_id_, pack.data(), pack.size() * common::utils::FIELDSIZE);
    for (size_t j = 0; j < lx; ++j) {
      r_share[j] = pack[2 * j];
      r0_share[j] = pack[2 * j + 1];
    }
  }

  std::vector<Field> u(lx, Field(0));
  for (size_t j = 1; j <= lx; ++j) {
    const uint64_t two_pow_j = pow2Bound(j);
    const uint64_t two_pow_lx_minus_1 = pow2Bound(lx - 1);
    Field z = x_share + ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(two_pow_lx_minus_1)) : Field(0));
    Field c_local =
        z + NTL::conv<Field>(NTL::to_ZZ(two_pow_j)) * r_share[j - 1] + r0_share[j - 1];
    Field c_open = openToComputingParties(c_local);
    const uint64_t c_u64 = NTL::conv<uint64_t>(NTL::rep(c_open));
    const uint64_t c0 = c_u64 & (two_pow_j - 1);
    Field d = ((id_ == 0) ? NTL::conv<Field>(NTL::to_ZZ(c0)) : Field(0)) - r0_share[j - 1];
    const Field inv2pow = inv(NTL::conv<Field>(NTL::to_ZZ(two_pow_j)));
    u[j - 1] = inv2pow * (x_share - d);
    if (stats != nullptr) {
      stats->batched_open_calls += 1;
    }
  }
  return u;
}

Field Protocol::bgtezCompare(const Field& x_share, size_t lx, size_t s, bool force_t,
                             bool forced_t_value, BGTEZStats* stats) {
  if (lx == 0) {
    throw std::runtime_error("bgtezCompare requires lx > 0");
  }
  if (lx + s + 1 >= 64) {
    throw std::runtime_error("bgtezCompare requires lx + s + 1 < 64");
  }
  if (id_ > helper_id_) {
    return Field(0);
  }

  const bool t = force_t ? forced_t_value : ((seed_ & 1) == 1);
  Field hat_x = t ? -x_share : x_share;
  Field u_star = (id_ == 0) ? (t ? Field(-1) : Field(1)) : Field(0);
  Field u0 = hat_x;

  auto u_trunc = batchedTruncateAll(hat_x, lx, s, stats);

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

  std::vector<Field> rho(lx + 2, Field(0));
  for (size_t i = 0; i < rho.size(); ++i) {
    auto prg = partyHelperRng(seed_ + 41000, 0, i + 1);
    rho[i] = randomField(prg);
    if (rho[i] == Field(0)) {
      rho[i] = Field(1);
    }
  }

  std::vector<Field> candidates(lx + 2, Field(0));
  candidates[0] = rho[0] * v_star;
  for (size_t j = 0; j <= lx; ++j) {
    candidates[j + 1] = rho[j + 1] * v[j];
  }
  std::vector<size_t> perm(candidates.size());
  std::iota(perm.begin(), perm.end(), 0);
  std::mt19937_64 shuf_rng(static_cast<uint64_t>(seed_) * 17ULL + 5ULL);
  std::shuffle(perm.begin(), perm.end(), shuf_rng);
  std::vector<Field> shuffled(candidates.size(), Field(0));
  for (size_t i = 0; i < candidates.size(); ++i) {
    shuffled[i] = candidates[perm[i]];
  }
  std::vector<Field> helper_payload = shuffled;
  helper_payload.push_back(hat_x);

  // round 2: send shuffled shares to helper
  const size_t bytes = helper_payload.size() * common::utils::FIELDSIZE;
  maybeSimulateStep(bytes);
  network_->send(helper_id_, helper_payload.data(), bytes);
  network_->flush();

  // round 3: helper shares back result bit
  Field bit_share = Field(0);
  if (id_ == helper_id_) {
    std::vector<Field> recv(helper_payload.size(), Field(0));
    std::vector<Field> sum(helper_payload.size(), Field(0));
    for (int p = 0; p < helper_id_; ++p) {
      network_->recv(p, recv.data(), bytes);
      for (size_t i = 0; i < shuffled.size(); ++i) {
        sum[i] += recv[i];
      }
      sum.back() += recv.back();
    }
    bool any_zero = false;
    for (const auto& val : sum) {
      if (val == Field(0)) {
        any_zero = true;
        break;
      }
    }
    const uint64_t opened_raw = NTL::conv<uint64_t>(NTL::rep(sum.back()));
    const uint64_t prime = 18446744073709551557ULL;
    int64_t opened_x = static_cast<int64_t>(opened_raw);
    if (opened_raw > (prime / 2ULL)) {
      opened_x = static_cast<int64_t>(opened_raw - prime);
    }
    Field bit = (opened_x >= 0 || any_zero) ? Field(1) : Field(0);
    std::vector<Field> back(helper_id_, Field(0));
    Field partial = Field(0);
    for (int p = 0; p <= helper_id_ - 2; ++p) {
      auto rg = helperTruncRng(seed_ + 42000, static_cast<size_t>(p));
      back[p] = randomField(rg);
      partial += back[p];
    }
    back[helper_id_ - 1] = bit - partial;
    for (int p = 0; p < helper_id_; ++p) {
      network_->send(p, &back[p], common::utils::FIELDSIZE);
    }
    network_->flush();
    return Field(0);
  }

  network_->recv(helper_id_, &bit_share, common::utils::FIELDSIZE);
  Field t_share = (id_ == 0 && t) ? Field(1) : Field(0);
  return t_share + bit_share - Field(2) * ((t) ? bit_share : Field(0));
}

}  // namespace asterisk2
