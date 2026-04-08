#include <io/netmp.h>

#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

#include "utils.h"
#include "Asterisk2.0/protocol.h"
#include "utils/types.h"

using common::utils::Field;
using json = nlohmann::json;
namespace bpo = boost::program_options;

void benchmark(const bpo::variables_map& opts) {
  const auto nP = opts["num-parties"].as<size_t>();
  const auto pid = opts["pid"].as<size_t>();
  const auto seed = opts["seed"].as<size_t>();
  const auto repeat = opts["repeat"].as<size_t>();
  const auto port = opts["port"].as<int>();
  const auto lx = opts["lx"].as<size_t>();
  const auto slack = opts["slack"].as<size_t>();
  const auto x_clear = opts["x-clear"].as<int64_t>();

  if (!opts["localhost"].as<bool>()) {
    throw std::runtime_error("BGTEZ benchmark currently supports localhost only");
  }

  auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, port, nullptr, true);
  common::utils::Circuit<Field> empty;
  auto level_circ = empty.orderGatesByLevel();

  json output_data;
  output_data["details"] = {{"num-parties", nP},
                            {"pid", pid},
                            {"seed", seed},
                            {"repeat", repeat},
                            {"lx", lx},
                            {"slack", slack},
                            {"x_clear", x_clear}};
  output_data["benchmarks"] = json::array();

  for (size_t r = 0; r < repeat; ++r) {
    asterisk2::Protocol proto(static_cast<int>(nP), static_cast<int>(pid), network, level_circ,
                              static_cast<int>(seed));

    Field x_share = Field(0);
    if (pid < nP) {
      x_share = (pid == 0) ? Field(x_clear) : Field(0);
    }

    network->sync();
    StatsPoint offline_start(*network);
    auto cmp_offline = proto.compare_offline(lx, slack, false, false);
    StatsPoint offline_end(*network);
    auto offline_bench = offline_end - offline_start;

    network->sync();
    StatsPoint online_start(*network);
    asterisk2::BGTEZStats stats;
    Field out_share = proto.compare_online(x_share, cmp_offline, &stats);
    StatsPoint online_end(*network);
    auto online_bench = online_end - online_start;

    size_t offline_bytes = 0;
    for (const auto& val : offline_bench["communication"]) {
      offline_bytes += val.get<int64_t>();
    }
    size_t online_bytes = 0;
    for (const auto& val : online_bench["communication"]) {
      online_bytes += val.get<int64_t>();
    }

    output_data["benchmarks"].push_back({
        {"offline", offline_bench},
        {"online", online_bench},
        {"offline_bytes", offline_bytes},
        {"online_bytes", online_bytes},
        {"bgtez_batched_open_calls", stats.batched_open_calls},
        {"output_share", (pid < nP) ? NTL::conv<uint64_t>(NTL::rep(out_share)) : 0},
    });
  }

  if (opts.count("output") != 0) {
    saveJson(output_data, opts["output"].as<std::string>());
  }
}

bpo::options_description programOptions() {
  bpo::options_description desc("Asterisk2.0 BGTEZ benchmark options");
  desc.add_options()
      ("num-parties,n", bpo::value<size_t>()->required(), "Number of computing parties.")
      ("pid,p", bpo::value<size_t>()->required(), "Party ID.")
      ("seed", bpo::value<size_t>()->default_value(200), "Value of the random seed.")
      ("repeat,r", bpo::value<size_t>()->default_value(1), "Number of repetitions.")
      ("lx", bpo::value<size_t>()->default_value(16), "Bit-length parameter lx.")
      ("slack", bpo::value<size_t>()->default_value(8), "Statistical slack parameter s.")
      ("x-clear", bpo::value<int64_t>()->default_value(123), "Clear signed input x.")
      ("localhost", bpo::bool_switch(), "All parties are on same machine.")
      ("port", bpo::value<int>()->default_value(10000), "Base port for networking.")
      ("output,o", bpo::value<std::string>(), "File to save benchmarks.");
  return desc;
}

int main(int argc, char* argv[]) {
  ZZ_p::init(conv<ZZ>(common::utils::kFieldPrimeDecimal));

  auto prog_opts(programOptions());
  bpo::options_description cmdline("Benchmark Asterisk2.0 BGTEZ protocol.");
  cmdline.add(prog_opts);
  cmdline.add_options()("help,h", "produce help message");

  bpo::variables_map opts;
  bpo::store(bpo::command_line_parser(argc, argv).options(cmdline).run(), opts);

  if (opts.count("help") != 0) {
    std::cout << cmdline << std::endl;
    return 0;
  }

  try {
    bpo::notify(opts);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }

  try {
    benchmark(opts);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << "\nFatal error" << std::endl;
    return 1;
  }

  return 0;
}
