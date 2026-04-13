#include <io/netmp.h>
#include <utils/circuit.h>

#include <algorithm>
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>
#include <vector>

#include "utils.h"
#include "Asterisk2.0/protocol.h"
#include "utils/network_cost_model.h"

using common::utils::Field;
using json = nlohmann::json;
namespace bpo = boost::program_options;

common::utils::Circuit<Field> generateCircuit(size_t gates_per_level, size_t depth) {
  common::utils::Circuit<Field> circ;

  std::vector<common::utils::wire_t> level_inputs(gates_per_level);
  std::generate(level_inputs.begin(), level_inputs.end(),
                [&]() { return circ.newInputWire(); });

  for (size_t d = 0; d < depth; ++d) {
    std::vector<common::utils::wire_t> level_outputs(gates_per_level);
    for (size_t i = 0; i < gates_per_level - 1; ++i) {
      level_outputs[i] = circ.addGate(common::utils::GateType::kMul,
                                      level_inputs[i], level_inputs[i + 1]);
    }
    level_outputs[gates_per_level - 1] =
        circ.addGate(common::utils::GateType::kMul,
                     level_inputs[gates_per_level - 1], level_inputs[0]);
    level_inputs = std::move(level_outputs);
  }

  for (auto i : level_inputs) {
    circ.setAsOutput(i);
  }

  return circ;
}

void benchmark(const bpo::variables_map& opts) {
  auto gates_per_level = opts["gates-per-level"].as<size_t>();
  auto depth = opts["depth"].as<size_t>();
  auto nP = opts["num-parties"].as<size_t>();
  auto pid = opts["pid"].as<size_t>();
  auto seed = opts["seed"].as<size_t>();
  auto repeat = opts["repeat"].as<size_t>();
  auto port = opts["port"].as<int>();
  auto security_model_str = opts["security-model"].as<std::string>();
  auto sim_latency_ms = opts["sim-latency-ms"].as<double>();
  auto sim_bandwidth_mbps = opts["sim-bandwidth-mbps"].as<double>();
  auto parallel_send = opts["parallel-send"].as<bool>();
  auto net_preset = opts["net-preset"].as<std::string>();
  auto bandwidth_bps = opts["bandwidth-bps"].as<uint64_t>();
  auto latency_ms = opts["latency-ms"].as<double>();
  auto net_model =
      common::utils::resolveNetworkCostModel(net_preset, bandwidth_bps, latency_ms);
  auto dump_output_shares = opts["dump-output-shares"].as<bool>();
  auto trunc_frac_bits = opts["trunc-frac-bits"].as<size_t>();
  auto trunc_lx = opts["trunc-lx"].as<size_t>();
  auto trunc_slack = opts["trunc-slack"].as<size_t>();

  asterisk2::SecurityModel security_model = asterisk2::SecurityModel::kSemiHonest;
  if (security_model_str == "malicious") {
    security_model = asterisk2::SecurityModel::kMalicious;
  } else if (security_model_str != "semi-honest") {
    throw std::runtime_error("Unsupported security-model, expected semi-honest or malicious");
  }

  std::shared_ptr<io::NetIOMP> network = nullptr;
  if (opts["localhost"].as<bool>()) {
    network = std::make_shared<io::NetIOMP>(pid, nP + 1, port, nullptr, true);
  } else {
    throw std::runtime_error("Asterisk2.0 benchmark currently supports localhost only");
  }

  auto circ = generateCircuit(gates_per_level, depth).orderGatesByLevel();
  size_t mul_depths = 0;
  for (const auto& level : circ.gates_by_level) {
    bool has_mul = false;
    for (const auto& gate : level) {
      if (gate->type == common::utils::GateType::kMul) {
        has_mul = true;
        break;
      }
    }
    if (has_mul) {
      ++mul_depths;
    }
  }

  std::unordered_map<common::utils::wire_t, Field> inputs;
  if (pid < nP) {
    for (const auto& g : circ.gates_by_level[0]) {
      if (g->type == common::utils::GateType::kInp) {
        inputs[g->out] = (pid == 0) ? Field(5) : Field(0);
      }
    }
  }

  json output_data;
  output_data["details"] = {{"gates_per_level", gates_per_level},
                            {"depth", depth},
                            {"num-parties", nP},
                            {"pid", pid},
                            {"seed", seed},
                            {"repeat", repeat},
                            {"security_model", security_model_str},
                            {"sim_latency_ms", sim_latency_ms},
                            {"sim_bandwidth_mbps", sim_bandwidth_mbps},
                            {"parallel_send", parallel_send},
                            {"net_preset", net_preset},
                            {"bandwidth_bps", net_model.bandwidth_bps},
                            {"latency_ms", net_model.latency_ms}};
  output_data["benchmarks"] = json::array();

  for (size_t r = 0; r < repeat; ++r) {
    asterisk2::ProtocolConfig cfg;
    cfg.security_model = security_model;
    cfg.sim_latency_ms = sim_latency_ms;
    cfg.sim_bandwidth_mbps = sim_bandwidth_mbps;
    cfg.parallel_send = parallel_send;
    asterisk2::Protocol proto(nP, pid, network, circ, static_cast<int>(seed), cfg);

    network->sync();
    StatsPoint offline_start(*network);
    auto off_data = proto.mul_offline();
    StatsPoint offline_end(*network);

    network->sync();
    StatsPoint online_start(*network);
    std::vector<Field> local_outputs;
    std::vector<Field> local_trunc_outputs;
    asterisk2::OnlineTimingStats online_timing_stats{};
    if (security_model == asterisk2::SecurityModel::kSemiHonest) {
      if (pid < nP) {
        local_outputs = proto.onlineSemiHonestForBenchmark(inputs, off_data.triples);
        online_timing_stats = proto.onlineTimingStats();
      }
    } else {
      // Malicious online path requires helper participation (e.g., input sharing).
      auto out = proto.mul_online(inputs, off_data);
      if (pid < nP) {
        local_outputs = std::move(out);
      }
    }
    StatsPoint online_end(*network);

    json trunc_offline_bench = {{"time", 0.0}, {"communication", json::array()}};
    json trunc_online_bench = {{"time", 0.0}, {"communication", json::array()}};
    size_t trunc_offline_bytes = 0;
    size_t trunc_online_bytes = 0;
    if (trunc_frac_bits > 0) {
      asterisk2::TruncOfflineData trunc_offline_data;
      network->sync();
      StatsPoint trunc_offline_start(*network);
      trunc_offline_data =
          proto.trunc_offline(circ.outputs.size(), trunc_lx, trunc_frac_bits, trunc_slack);
      StatsPoint trunc_offline_end(*network);
      trunc_offline_bench = trunc_offline_end - trunc_offline_start;
      for (const auto& val : trunc_offline_bench["communication"]) {
        trunc_offline_bytes += val.get<int64_t>();
      }

      network->sync();
      StatsPoint trunc_online_start(*network);
      if (pid < nP) {
        local_trunc_outputs = proto.trunc_online(local_outputs, trunc_offline_data);
      } else {
        std::vector<Field> helper_placeholder(circ.outputs.size(), Field(0));
        (void)proto.trunc_online(helper_placeholder, trunc_offline_data);
      }
      StatsPoint trunc_online_end(*network);
      trunc_online_bench = trunc_online_end - trunc_online_start;
      for (const auto& val : trunc_online_bench["communication"]) {
        trunc_online_bytes += val.get<int64_t>();
      }
    }

    auto offline_bench = offline_end - offline_start;
    auto online_bench = online_end - online_start;

    size_t offline_bytes = 0;
    for (const auto& val : offline_bench["communication"]) {
      offline_bytes += val.get<int64_t>();
    }
    size_t online_bytes = 0;
    for (const auto& val : online_bench["communication"]) {
      online_bytes += val.get<int64_t>();
    }

    // Communication counters:
    // - offline_comm_count: helper sends one triple tuple per multiplication gate to Pn.
    // - online_comm_rounds: batched-open does one interactive round per multiplicative depth.
    // - online_send_count: if parallel_send=true, count one logical round-send;
    //   else count per-peer sends.
    size_t mul_gates = gates_per_level * depth;
    size_t offline_comm_count = (pid == nP ? mul_gates : 0);
    size_t online_comm_rounds = (pid < nP ? mul_depths : 0);
    size_t online_send_count = 0;
    if (pid < nP) {
      online_send_count = parallel_send ? mul_depths : mul_depths * (nP - 1);
    }
    // Simplified communication model:
    //   round_time = latency_ms + (bytes * 8) * 1000 / bandwidth_bps
    // All-to-all variant (shared egress, one message per peer):
    //   round_time = latency_ms + (msg_size_bytes * (n-1) * 8) * 1000 / bandwidth_bps
    // This ignores queueing delay and protocol overhead.
    double comm_model_round_ms = 0.0;
    double comm_model_total_ms = 0.0;
    if (pid < nP && common::utils::isNetworkCostModelEnabled(net_model)) {
      const size_t msg_size_bytes = 2 * gates_per_level * common::utils::FIELDSIZE;
      comm_model_round_ms =
          common::utils::estimateAllToAllRoundTimeMs(msg_size_bytes, nP, net_model);
      comm_model_total_ms =
          common::utils::estimateTotalTimeMs(comm_model_round_ms, online_comm_rounds);
      std::cout << "comm_model_round_ms: " << comm_model_round_ms << "\n";
      std::cout << "comm_model_total_ms: " << comm_model_total_ms << "\n";
    }

    json row = {
        {"offline", offline_bench},
        {"online", online_bench},
        {"truncation_offline", trunc_offline_bench},
        {"truncation", trunc_online_bench},
        {"offline_bytes", offline_bytes},
        {"online_bytes", online_bytes},
        {"truncation_offline_bytes", trunc_offline_bytes},
        {"truncation_bytes", trunc_online_bytes},
        {"offline_comm_count", offline_comm_count},
        {"online_comm_rounds", online_comm_rounds},
        {"online_send_count", online_send_count},
        {"online_local_compute_ms", online_timing_stats.local_compute_ms},
        {"online_network_overhead_ms", online_timing_stats.network_overhead_ms},
        {"comm_model_round_ms", comm_model_round_ms},
        {"comm_model_total_ms", comm_model_total_ms},
        // keep online_comm_count for compatibility; now it denotes rounds.
        {"online_comm_count", online_comm_rounds},
    };
    if (pid < nP && dump_output_shares) {
      json shares = json::array();
      for (const auto& val : local_outputs) {
        shares.push_back(NTL::conv<uint64_t>(NTL::rep(val)));
      }
      row["local_output_shares"] = shares;
      if (trunc_frac_bits > 0) {
        json trunc_shares = json::array();
        for (const auto& val : local_trunc_outputs) {
          trunc_shares.push_back(NTL::conv<uint64_t>(NTL::rep(val)));
        }
        row["local_trunc_output_shares"] = trunc_shares;
      }
    }
    output_data["benchmarks"].push_back(std::move(row));
  }

  if (opts.count("output") != 0) {
    saveJson(output_data, opts["output"].as<std::string>());
  }
}

bpo::options_description programOptions() {
  bpo::options_description desc("Asterisk2.0 half-honest Beaver benchmark options");
  desc.add_options()
      ("gates-per-level,g", bpo::value<size_t>()->required(), "Number of gates at each level.")
      ("depth,d", bpo::value<size_t>()->required(), "Multiplicative depth of circuit.")
      ("num-parties,n", bpo::value<size_t>()->required(), "Number of computing parties.")
      ("pid,p", bpo::value<size_t>()->required(), "Party ID.")
      ("seed", bpo::value<size_t>()->default_value(200), "Value of the random seed.")
      ("localhost", bpo::bool_switch(), "All parties are on same machine.")
      ("security-model", bpo::value<std::string>()->default_value("semi-honest"),
       "Security model: semi-honest or malicious.")
      ("sim-latency-ms", bpo::value<double>()->default_value(0.0),
       "Simulated per-step latency in milliseconds.")
      ("sim-bandwidth-mbps", bpo::value<double>()->default_value(0.0),
       "Simulated bandwidth cap in Mbps (<=0 disables).")
      ("parallel-send", bpo::bool_switch()->default_value(false),
       "Enable parallel peer send/recv for sufficiently wide levels; report one logical send per round.")
      ("net-preset", bpo::value<std::string>()->default_value("none"),
       "Communication-cost preset: none|lan|wan.")
      ("bandwidth-bps", bpo::value<uint64_t>()->default_value(0),
       "Communication-cost model bandwidth in bps (overrides preset when >0).")
      ("latency-ms", bpo::value<double>()->default_value(0.0),
       "Communication-cost model latency in ms (overrides preset when >0).")
      ("dump-output-shares", bpo::bool_switch()->default_value(false),
       "Dump local output shares in benchmark JSON for correctness validation.")
      ("trunc-frac-bits", bpo::value<size_t>()->default_value(0),
       "Enable Asterisk2.0 probabilistic truncation with this many fractional bits.")
      ("trunc-lx", bpo::value<size_t>()->default_value(40),
       "Bit-length parameter ell_x for probabilistic truncation.")
      ("trunc-slack", bpo::value<size_t>()->default_value(8),
       "Statistical slack parameter s for probabilistic truncation.")
      ("port", bpo::value<int>()->default_value(10000), "Base port for networking.")
      ("output,o", bpo::value<std::string>(), "File to save benchmarks.")
      ("repeat,r", bpo::value<size_t>()->default_value(1), "Number of repetitions.");
  return desc;
}

int main(int argc, char* argv[]) {
  ZZ_p::init(conv<ZZ>(common::utils::kFieldPrimeDecimal));

  auto prog_opts(programOptions());
  bpo::options_description cmdline("Benchmark Asterisk2.0 half-honest multiplication protocol.");
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
    if (!opts["localhost"].as<bool>()) {
      throw std::runtime_error("Expected --localhost");
    }
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
