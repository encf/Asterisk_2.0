#define BOOST_TEST_MODULE asterisk2_truncation
#include <boost/test/included/unit_test.hpp>

#include <future>
#include <memory>
#include <vector>

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

BOOST_AUTO_TEST_CASE(probabilistic_truncation_correctness) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int helper = nP;
  constexpr int base_port = 22000;
  constexpr size_t ell_x = 40;
  constexpr size_t m = 8;
  constexpr size_t s = 8;
  constexpr uint64_t x_clear = 123456;

  common::utils::Circuit<Field> empty_circ;
  auto level_circ = empty_circ.orderGatesByLevel();

  std::vector<std::future<Field>> parties;
  parties.reserve(nP + 1);
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [&, pid]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::Protocol proto(nP, pid, network, level_circ, 200);

      std::vector<Field> x_share(1, Field(0));
      if (pid == 0) {
        x_share[0] = Field(x_clear);
      }

      auto trunc = proto.probabilisticTruncate(x_share, ell_x, m, s);
      if (pid == helper) {
        return Field(0);
      }
      BOOST_REQUIRE_EQUAL(trunc.size(), 1);
      return trunc[0];
    }));
  }

  Field y = Field(0);
  for (int pid = 0; pid <= nP; ++pid) {
    auto share = parties[pid].get();
    if (pid < nP) {
      y += share;
    }
  }

  const uint64_t y_u64 = NTL::conv<uint64_t>(NTL::rep(y));
  const uint64_t floor_val = x_clear >> m;
  const bool ok = (y_u64 == floor_val) || (y_u64 == floor_val + 1);
  BOOST_TEST(ok);
}

BOOST_AUTO_TEST_CASE(trunc_online_requires_offline_data) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int base_port = 22100;

  common::utils::Circuit<Field> empty_circ;
  auto level_circ = empty_circ.orderGatesByLevel();

  std::vector<std::future<bool>> parties;
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [&, pid]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::Protocol proto(nP, pid, network, level_circ, 200);
      if (pid == 0) {
        asterisk2::TruncOfflineData missing;
        BOOST_CHECK_THROW((void)proto.trunc_online({Field(9)}, missing), std::runtime_error);
      }
      return true;
    }));
  }
  for (auto& fut : parties) {
    BOOST_CHECK(fut.get());
  }
}

BOOST_AUTO_TEST_CASE(trunc_offline_online_equivalent_to_legacy_api) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  constexpr int nP = 3;
  constexpr int helper = nP;
  constexpr int base_port_legacy = 22200;
  constexpr int base_port_split = 22300;
  constexpr size_t ell_x = 40;
  constexpr size_t m = 8;
  constexpr size_t s = 8;
  constexpr uint64_t x_clear = 123456;

  common::utils::Circuit<Field> empty_circ;
  auto level_circ = empty_circ.orderGatesByLevel();

  auto run = [&](int base_port, bool use_split) {
    std::vector<std::future<Field>> parties;
    for (int pid = 0; pid <= nP; ++pid) {
      parties.push_back(std::async(std::launch::async, [&, pid]() {
        ZZ_p_ctx.restore();
        auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
        asterisk2::Protocol proto(nP, pid, network, level_circ, 200);
        std::vector<Field> x_share(1, Field(0));
        if (pid == 0) {
          x_share[0] = Field(x_clear);
        }
        if (use_split) {
          auto off = proto.trunc_offline(x_share.size(), ell_x, m, s);
          auto out = proto.trunc_online(x_share, off);
          return (pid == helper) ? Field(0) : out[0];
        }
        auto out = proto.probabilisticTruncate(x_share, ell_x, m, s);
        return (pid == helper) ? Field(0) : out[0];
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
