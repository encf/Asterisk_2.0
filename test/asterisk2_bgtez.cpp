#define BOOST_TEST_MODULE asterisk2_bgtez
#include <boost/test/included/unit_test.hpp>

#include <future>
#include <fstream>
#include <memory>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <atomic>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <io/netmp.h>
#include <utils/circuit.h>

#include "Asterisk2.0/protocol.h"
#include "utils/types.h"

using common::utils::Field;

struct GlobalFixture {
  GlobalFixture() { NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(common::utils::kFieldPrimeDecimal)); }
};
BOOST_GLOBAL_FIXTURE(GlobalFixture);

namespace {
constexpr int nP = 3;
int fresh_port() {
  static std::atomic<int> next{50000 + static_cast<int>(getpid() % 1000)};
  while (true) {
    int base = next.fetch_add(128);
    bool ok = true;
    std::vector<int> fds;
    for (int p = base; p <= base + 32; ++p) {
      int fd = ::socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0) {
        ok = false;
        break;
      }
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      addr.sin_port = htons(static_cast<uint16_t>(p));
      if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ok = false;
        ::close(fd);
        break;
      }
      fds.push_back(fd);
    }
    for (int fd : fds) {
      ::close(fd);
    }
    if (ok) {
      return base;
    }
  }
}

std::vector<Field> run_bgtez_once(int x_clear, size_t lx, size_t s, int base_port,
                                  bool force_t = true, bool t_val = false,
                                  asterisk2::BGTEZStats* stat_out = nullptr) {
  common::utils::Circuit<Field> empty;
  auto level = empty.orderGatesByLevel();
  NTL::ZZ_pContext ctx;
  ctx.save();
  std::vector<std::future<std::pair<Field, asterisk2::BGTEZStats>>> parties;
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [=, &ctx]() {
      ctx.restore();
      auto net = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::Protocol p(nP, pid, net, level, 200);
      Field share = (pid == 0) ? Field(x_clear) : Field(0);
      asterisk2::BGTEZStats st;
      auto off = p.compare_offline(lx, s, force_t, t_val);
      Field out = p.compare_online(share, off, &st);
      return std::make_pair(out, st);
    }));
  }

  std::vector<Field> out(nP + 1, Field(0));
  for (int pid = 0; pid <= nP; ++pid) {
    auto [val, st] = parties[pid].get();
    out[pid] = val;
    if (stat_out != nullptr && pid == 0) {
      *stat_out = st;
    }
  }
  return out;
}

std::vector<Field> run_trunc_all(bool batched, int x_clear, size_t lx, size_t s, int base_port,
                                 asterisk2::BGTEZStats* stat_out = nullptr) {
  common::utils::Circuit<Field> empty;
  auto level = empty.orderGatesByLevel();
  NTL::ZZ_pContext ctx;
  ctx.save();
  std::vector<std::future<std::pair<std::vector<Field>, asterisk2::BGTEZStats>>> parties;
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [=, &ctx]() {
      ctx.restore();
      auto net = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::Protocol p(nP, pid, net, level, 200);
      Field share = (pid == 0) ? Field(x_clear) : Field(0);
      asterisk2::BGTEZStats st;
      std::vector<Field> out = batched ? p.batchedTruncateAll(share, lx, s, &st)
                                       : p.serialTruncateAllForTesting(share, lx, s, &st);
      return std::make_pair(out, st);
    }));
  }

  std::vector<Field> rec(lx, Field(0));
  for (int pid = 0; pid <= nP; ++pid) {
    auto [vals, st] = parties[pid].get();
    if (pid < nP) {
      BOOST_REQUIRE_EQUAL(vals.size(), lx);
      for (size_t i = 0; i < lx; ++i) {
        rec[i] += vals[i];
      }
    }
    if (stat_out != nullptr && pid == 0) {
      *stat_out = st;
    }
  }
  return rec;
}

std::tuple<std::vector<Field>, std::vector<Field>, std::vector<Field>> run_bgtez_malicious_once(
    int x_clear, size_t lx, size_t s, int base_port, bool force_t = true, bool t_val = false) {
  common::utils::Circuit<Field> circ;
  auto w0 = circ.newInputWire();
  auto level = circ.orderGatesByLevel();
  NTL::ZZ_pContext ctx;
  ctx.save();
  std::vector<std::future<std::tuple<Field, Field, Field>>> parties;
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [=, &ctx]() {
      ctx.restore();
      auto net = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::ProtocolConfig cfg;
      cfg.security_model = asterisk2::SecurityModel::kMalicious;
      asterisk2::Protocol p(nP, pid, net, level, 200, cfg);
      auto mul_off = p.mul_offline();
      net->sync();

      std::unordered_map<common::utils::wire_t, Field> inputs;
      inputs[w0] = (pid == 0) ? Field(x_clear) : Field(0);
      auto auth_in = p.maliciousInputShareForTesting(inputs, mul_off);
      Field x_share = Field(0);
      Field dx_share = Field(0);
      auto off = p.compare_offline_malicious(lx, s, force_t, t_val);
      if (pid < nP) {
        x_share = auth_in.x_shares.at(w0);
        dx_share = auth_in.delta_x_shares.at(w0);
      }
      auto out = p.compare_online_malicious(x_share, dx_share, off);
      return std::make_tuple(out.gtez_share, out.delta_gtez_share, off.delta_share);
    }));
  }

  std::vector<Field> g(nP + 1, Field(0));
  std::vector<Field> dg(nP + 1, Field(0));
  std::vector<Field> delta(nP + 1, Field(0));
  for (int pid = 0; pid <= nP; ++pid) {
    auto [gi, dgi, di] = parties[pid].get();
    g[pid] = gi;
    dg[pid] = dgi;
    delta[pid] = di;
  }
  return {g, dg, delta};
}
}  // namespace

BOOST_AUTO_TEST_CASE(batched_vs_serial_equivalence) {
  constexpr size_t lx = 8;
  constexpr size_t s = 8;
  for (int x : {0, 1, 7, 123, 255}) {
    auto b = run_trunc_all(true, x, lx, s, fresh_port());
    auto r = run_trunc_all(false, x, lx, s, fresh_port());
    BOOST_TEST(b == r, "batched truncation must match serial truncation");
  }
}

BOOST_AUTO_TEST_CASE(communication_pattern_single_batched_open) {
  constexpr size_t lx = 8;
  constexpr size_t s = 8;
  asterisk2::BGTEZStats bstat, sstat;
  (void)run_trunc_all(true, 77, lx, s, fresh_port(), &bstat);
  (void)run_trunc_all(false, 77, lx, s, fresh_port(), &sstat);
  BOOST_TEST(bstat.batched_open_calls == 1u);
  BOOST_TEST(sstat.batched_open_calls == lx);
}

BOOST_AUTO_TEST_CASE(end_to_end_bgtez_correctness) {
  constexpr size_t lx = 16;
  constexpr size_t s = 8;
  for (int x : {-200, -1, 0, 1, 123, 32767}) {
    auto shares = run_bgtez_once(x, lx, s, fresh_port());
    Field rec = Field(0);
    for (int pid = 0; pid < nP; ++pid) {
      rec += shares[pid];
    }
    const int got = NTL::conv<uint64_t>(NTL::rep(rec)) % 2;
    const int expect = (x >= 0) ? 1 : 0;
    BOOST_TEST(got == expect);
  }
}

BOOST_AUTO_TEST_CASE(sign_blinding_consistency) {
  constexpr size_t lx = 16;
  constexpr size_t s = 8;
  int x = 1234;
  auto s0 = run_bgtez_once(x, lx, s, fresh_port(), true, false);
  auto s1 = run_bgtez_once(x, lx, s, fresh_port(), true, true);
  Field r0 = Field(0), r1 = Field(0);
  for (int pid = 0; pid < nP; ++pid) {
    r0 += s0[pid];
    r1 += s1[pid];
  }
  BOOST_TEST((NTL::conv<uint64_t>(NTL::rep(r0)) % 2) == 1u);
  BOOST_TEST((NTL::conv<uint64_t>(NTL::rep(r1)) % 2) == 1u);
}

BOOST_AUTO_TEST_CASE(shuffle_invariance_deterministic_seed) {
  constexpr size_t lx = 16;
  constexpr size_t s = 8;
  auto a = run_bgtez_once(-9, lx, s, fresh_port());
  auto b = run_bgtez_once(-9, lx, s, fresh_port());
  Field ra = Field(0), rb = Field(0);
  for (int pid = 0; pid < nP; ++pid) {
    ra += a[pid];
    rb += b[pid];
  }
  BOOST_TEST((NTL::conv<uint64_t>(NTL::rep(ra)) % 2) == (NTL::conv<uint64_t>(NTL::rep(rb)) % 2));
}

BOOST_AUTO_TEST_CASE(mask_shape_regression) {
  constexpr size_t lx = 12;
  constexpr size_t s = 8;
  auto b = run_trunc_all(true, 91, lx, s, fresh_port());
  BOOST_REQUIRE_EQUAL(b.size(), lx);
  bool any_diff = false;
  for (size_t i = 1; i < b.size(); ++i) {
    any_diff = any_diff || (b[i] != b[0]);
  }
  BOOST_TEST(any_diff);
}

BOOST_AUTO_TEST_CASE(helper_zero_detection_regression) {
  constexpr size_t lx = 16;
  constexpr size_t s = 8;
  auto pos = run_bgtez_once(55, lx, s, fresh_port());
  auto neg = run_bgtez_once(-55, lx, s, fresh_port());
  Field rpos = Field(0), rneg = Field(0);
  for (int pid = 0; pid < nP; ++pid) {
    rpos += pos[pid];
    rneg += neg[pid];
  }
  BOOST_TEST((NTL::conv<uint64_t>(NTL::rep(rpos)) % 2) == 1u);
  BOOST_TEST((NTL::conv<uint64_t>(NTL::rep(rneg)) % 2) == 0u);
}

BOOST_AUTO_TEST_CASE(compare_online_requires_offline_data) {
  NTL::ZZ_pContext ctx;
  ctx.save();
  constexpr int base_port = 22600;
  common::utils::Circuit<Field> empty;
  auto level = empty.orderGatesByLevel();
  std::vector<std::future<bool>> parties;
  for (int pid = 0; pid <= nP; ++pid) {
    parties.push_back(std::async(std::launch::async, [=, &ctx]() {
      ctx.restore();
      auto net = std::make_shared<io::NetIOMP>(pid, nP + 1, base_port, nullptr, true);
      asterisk2::Protocol p(nP, pid, net, level, 200);
      if (pid == 0) {
        asterisk2::CompareOfflineData missing;
        BOOST_CHECK_THROW((void)p.compare_online(Field(5), missing), std::runtime_error);
      }
      return true;
    }));
  }
  for (auto& fut : parties) {
    BOOST_CHECK(fut.get());
  }
}

BOOST_AUTO_TEST_CASE(malicious_compare_authenticated_correctness) {
  constexpr size_t lx = 16;
  constexpr size_t s = 8;
  for (int x : {-200, -1, 0, 1, 123, 32767}) {
    auto [g_shares, dg_shares, delta_shares] =
        run_bgtez_malicious_once(x, lx, s, fresh_port(), true, false);
    Field g = Field(0);
    Field dg = Field(0);
    Field delta = Field(0);
    for (int pid = 0; pid < nP; ++pid) {
      g += g_shares[pid];
      dg += dg_shares[pid];
      delta += delta_shares[pid];
    }
    const int got = NTL::conv<uint64_t>(NTL::rep(g)) % 2;
    const int expect = (x >= 0) ? 1 : 0;
    BOOST_TEST(got == expect);
    BOOST_TEST(dg == delta * g);
  }
}

BOOST_AUTO_TEST_CASE(prg_and_parallel_networking_regression_guard) {
  std::ifstream in("../../src/Asterisk2.0/protocol.cpp");
  if (!in.good()) {
    in.open("../src/Asterisk2.0/protocol.cpp");
  }
  BOOST_REQUIRE(in.good());
  std::stringstream ss;
  ss << in.rdbuf();
  const std::string code = ss.str();

  BOOST_TEST(code.find("mt19937") == std::string::npos);
  BOOST_TEST(code.find("sendFieldVectorToPeers(") != std::string::npos);
  BOOST_TEST(code.find("recvFieldVectorsFromPeers(") != std::string::npos);
}
