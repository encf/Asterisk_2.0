#define BOOST_TEST_MODULE asterisk2_multiplication
#include <boost/test/included/unit_test.hpp>

#include <future>
#include <memory>
#include <unordered_map>

#include <io/netmp.h>
#include <utils/circuit.h>

#include "Asterisk2.0/protocol.h"
#include "utils/types.h"

using common::utils::Field;

struct GlobalFixture {
  GlobalFixture() {
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(common::utils::kFieldPrimeDecimal));
  }
};
BOOST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_AUTO_TEST_CASE(single_mul_correctness) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int helper = nP;
  constexpr int base_port = 21000;

  common::utils::Circuit<Field> circ;
  auto w0 = circ.newInputWire();
  auto w1 = circ.newInputWire();
  auto wm = circ.addGate(common::utils::GateType::kMul, w0, w1);
  circ.setAsOutput(wm);
  auto level_circ = circ.orderGatesByLevel();

  std::vector<std::future<Field>> parties;
  parties.reserve(nP + 1);
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [&, pid]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::Protocol proto(nP, pid, network, level_circ, 200);

      auto triples = proto.offline();
      network->sync();

      if (pid == helper) {
        return Field(0);
      }

      std::unordered_map<common::utils::wire_t, Field> inputs;
      inputs[w0] = (pid == 0) ? Field(7) : Field(0);
      inputs[w1] = (pid == 0) ? Field(9) : Field(0);
      auto out = proto.online(inputs, triples);
      BOOST_REQUIRE_EQUAL(out.size(), 1);
      return out[0];
    }));
  }

  Field rec = Field(0);
  for (int pid = 0; pid <= nP; ++pid) {
    auto share = parties[pid].get();
    if (pid < nP) {
      rec += share;
    }
  }

  BOOST_TEST(rec == Field(63));
}

BOOST_AUTO_TEST_CASE(mul_online_requires_offline_data) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int base_port = 21100;

  common::utils::Circuit<Field> circ;
  auto w0 = circ.newInputWire();
  auto w1 = circ.newInputWire();
  auto wm = circ.addGate(common::utils::GateType::kMul, w0, w1);
  circ.setAsOutput(wm);
  auto level_circ = circ.orderGatesByLevel();

  std::vector<std::future<bool>> parties;
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [&, pid]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::Protocol proto(nP, pid, network, level_circ, 200);
      if (pid == 0) {
        std::unordered_map<common::utils::wire_t, Field> inputs;
        inputs[w0] = Field(3);
        inputs[w1] = Field(4);
        asterisk2::MulOfflineData missing;
        BOOST_CHECK_THROW(proto.mul_online(inputs, missing), std::runtime_error);
      }
      return true;
    }));
  }
  for (auto& fut : parties) {
    BOOST_CHECK(fut.get());
  }
}

BOOST_AUTO_TEST_CASE(mul_offline_online_equivalent_to_legacy_api) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int helper = nP;
  constexpr int base_port_legacy = 21200;
  constexpr int base_port_split = 21300;

  common::utils::Circuit<Field> circ;
  auto w0 = circ.newInputWire();
  auto w1 = circ.newInputWire();
  auto wm = circ.addGate(common::utils::GateType::kMul, w0, w1);
  circ.setAsOutput(wm);
  auto level_circ = circ.orderGatesByLevel();

  auto run = [&](int base_port, bool use_split) {
    std::vector<std::future<Field>> parties;
    for (int pid = 0; pid <= nP; ++pid) {
      parties.push_back(std::async(std::launch::async, [&, pid]() {
        ZZ_p_ctx.restore();
        auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
        asterisk2::Protocol proto(nP, pid, network, level_circ, 200);
        if (pid == helper) {
          if (use_split) {
            (void)proto.mul_offline();
          } else {
            (void)proto.offline();
          }
          return Field(0);
        }
        std::unordered_map<common::utils::wire_t, Field> inputs;
        inputs[w0] = (pid == 0) ? Field(11) : Field(0);
        inputs[w1] = (pid == 0) ? Field(13) : Field(0);
        if (use_split) {
          auto off = proto.mul_offline();
          auto out = proto.mul_online(inputs, off);
          return out[0];
        }
        auto triples = proto.offline();
        auto out = proto.online(inputs, triples);
        return out[0];
      }));
    }
    Field rec = Field(0);
    for (int pid = 0; pid <= nP; ++pid) {
      auto share = parties[pid].get();
      if (pid < nP) {
        rec += share;
      }
    }
    return rec;
  };

  BOOST_TEST(run(base_port_legacy, false) == run(base_port_split, true));
}

BOOST_AUTO_TEST_CASE(malicious_mode_mul_roundtrip_smoke) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int helper = nP;
  constexpr int base_port = 21400;

  common::utils::Circuit<Field> circ;
  auto w0 = circ.newInputWire();
  auto w1 = circ.newInputWire();
  auto wm = circ.addGate(common::utils::GateType::kMul, w0, w1);
  circ.setAsOutput(wm);
  auto level_circ = circ.orderGatesByLevel();

  std::vector<std::future<Field>> parties;
  parties.reserve(nP + 1);
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [&, pid]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::ProtocolConfig cfg;
      cfg.security_model = asterisk2::SecurityModel::kMalicious;
      asterisk2::Protocol proto(nP, pid, network, level_circ, 200, cfg);

      auto off = proto.mul_offline();
      network->sync();
      std::unordered_map<common::utils::wire_t, Field> inputs;
      inputs[w0] = (pid == 0) ? Field(5) : Field(0);
      inputs[w1] = (pid == 0) ? Field(8) : Field(0);
      auto out = proto.mul_online(inputs, off);
      if (pid == helper) {
        return Field(0);
      }
      BOOST_REQUIRE_EQUAL(out.size(), 1);
      return out[0];
    }));
  }

  Field rec = Field(0);
  for (int pid = 0; pid <= nP; ++pid) {
    auto share = parties[pid].get();
    if (pid < nP) {
      rec += share;
    }
  }

  BOOST_TEST(rec == Field(40));
}

BOOST_AUTO_TEST_CASE(malicious_input_sharing_consistency_checked_in_test) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int helper = nP;
  constexpr int base_port = 21460;
  constexpr int input_value = 17;

  common::utils::Circuit<Field> circ;
  auto w0 = circ.newInputWire();
  auto level_circ = circ.orderGatesByLevel();

  struct SharePack {
    Field x{Field(0)};
    Field dx{Field(0)};
    Field delta_share{Field(0)};
  };

  std::vector<std::future<SharePack>> parties;
  parties.reserve(nP + 1);
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [&, pid]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::ProtocolConfig cfg;
      cfg.security_model = asterisk2::SecurityModel::kMalicious;
      asterisk2::Protocol proto(nP, pid, network, level_circ, 200, cfg);

      auto off = proto.mul_offline();
      network->sync();
      std::unordered_map<common::utils::wire_t, Field> inputs;
      inputs[w0] = (pid == 0) ? Field(input_value) : Field(0);
      const auto shares = proto.maliciousInputShareForTesting(inputs, off);
      if (pid == helper) {
        return SharePack{};
      }

      SharePack out;
      out.x = shares.x_shares.at(w0);
      out.dx = shares.delta_x_shares.at(w0);
      out.delta_share = off.delta_share;
      return out;
    }));
  }

  Field sum_x = Field(0);
  Field sum_dx = Field(0);
  Field delta = Field(0);
  for (int pid = 0; pid <= nP; ++pid) {
    const auto pack = parties[pid].get();
    if (pid < nP) {
      sum_x += pack.x;
      sum_dx += pack.dx;
      delta += pack.delta_share;
    }
  }

  BOOST_TEST(sum_x == Field(input_value));
  BOOST_TEST(sum_dx == delta * sum_x);
}

BOOST_AUTO_TEST_CASE(malicious_offline_generates_authenticated_auxiliary_tuples) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int helper = nP;
  constexpr int base_port = 21520;

  common::utils::Circuit<Field> circ;
  auto w0 = circ.newInputWire();
  auto w1 = circ.newInputWire();
  auto wm = circ.addGate(common::utils::GateType::kMul, w0, w1);
  circ.setAsOutput(wm);
  auto level_circ = circ.orderGatesByLevel();

  struct OfflinePack {
    asterisk2::TripleShare triple;
    asterisk2::MulAuthTupleShare auth;
  };

  std::vector<std::future<OfflinePack>> parties;
  parties.reserve(nP + 1);
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [&, pid]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::ProtocolConfig cfg;
      cfg.security_model = asterisk2::SecurityModel::kMalicious;
      asterisk2::Protocol proto(nP, pid, network, level_circ, 200, cfg);
      auto off = proto.mul_offline();

      OfflinePack out{};
      if (pid < nP) {
        BOOST_REQUIRE_EQUAL(off.triples.size(), 1);
        BOOST_REQUIRE_EQUAL(off.auth_tuples.size(), 1);
        out.triple = off.triples[0];
        out.auth = off.auth_tuples[0];
      }
      return out;
    }));
  }

  Field a = Field(0), b = Field(0), ab = Field(0);
  Field a_prime = Field(0), b_prime = Field(0), c_prime = Field(0);
  Field a_prime_b_prime = Field(0), a_prime_c_prime = Field(0), b_prime_c_prime = Field(0);
  Field a_prime_b_prime_c_prime = Field(0);
  for (int pid = 0; pid <= nP; ++pid) {
    const auto pack = parties[pid].get();
    if (pid < nP) {
      a += pack.triple.a;
      b += pack.triple.b;
      ab += pack.triple.c;
      a_prime += pack.auth.a_prime;
      b_prime += pack.auth.b_prime;
      c_prime += pack.auth.c_prime;
      a_prime_b_prime += pack.auth.a_prime_b_prime;
      a_prime_c_prime += pack.auth.a_prime_c_prime;
      b_prime_c_prime += pack.auth.b_prime_c_prime;
      a_prime_b_prime_c_prime += pack.auth.a_prime_b_prime_c_prime;
    }
  }

  BOOST_TEST(ab == a * b);
  BOOST_TEST(a_prime_b_prime == a_prime * b_prime);
  BOOST_TEST(a_prime_c_prime == a_prime * c_prime);
  BOOST_TEST(b_prime_c_prime == b_prime * c_prime);
  BOOST_TEST(a_prime_b_prime_c_prime == a_prime * b_prime * c_prime);
}
