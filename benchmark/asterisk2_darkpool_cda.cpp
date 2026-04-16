#include <io/netmp.h>
#include <utils/circuit.h>
#include <utils/darkpool.h>

#include <boost/program_options.hpp>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "Asterisk2.0/app_evaluator.h"
#include "utils.h"

using common::utils::Field;
using json = nlohmann::json;
namespace bpo = boost::program_options;

void benchmark(const bpo::variables_map& opts) {
  const auto buy_list_size = opts["buy-list-size"].as<size_t>();
  const auto sell_list_size = opts["sell-list-size"].as<size_t>();
  const auto nP = opts["num-parties"].as<size_t>();
  const auto pid = opts["pid"].as<size_t>();
  const auto seed = opts["seed"].as<size_t>();
  const auto repeat = opts["repeat"].as<size_t>();
  const auto port = opts["port"].as<int>();
  const auto lx = opts["lx"].as<size_t>();
  const auto slack = opts["slack"].as<size_t>();
  const auto security_model_str = opts["security-model"].as<std::string>();
  const auto new_order_name = opts["new-order-name"].as<int64_t>();
  const auto new_order_unit = opts["new-order-unit"].as<int64_t>();
  const auto new_order_price = opts["new-order-price"].as<int64_t>();

  asterisk2::SecurityModel security_model = asterisk2::SecurityModel::kSemiHonest;
  if (security_model_str == "malicious") {
    security_model = asterisk2::SecurityModel::kMalicious;
  } else if (security_model_str != "semi-honest") {
    throw std::runtime_error("Unsupported security-model, expected semi-honest or malicious");
  }

  if (!opts["localhost"].as<bool>()) {
    throw std::runtime_error("Asterisk2.0 Dark Pool CDA benchmark currently supports localhost only");
  }

  auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, port, nullptr, true);

  common::utils::DarkPool<Field> darkpool_ob(sell_list_size, buy_list_size);
  darkpool_ob.resizeList();
  const auto& cda_circuit = darkpool_ob.getCDACircuit();
  auto level_circ = cda_circuit.orderGatesByLevel();

  std::unordered_map<common::utils::wire_t, Field> clear_inputs;
  std::unordered_map<common::utils::wire_t, Field> shared_inputs;
  std::vector<Field> ordered_values = {Field(new_order_name), Field(new_order_unit),
                                       Field(new_order_price)};
  size_t input_idx = 0;
  for (const auto& level : level_circ.gates_by_level) {
    for (const auto& gate : level) {
      if (gate->type == common::utils::GateType::kInp) {
        if (input_idx >= ordered_values.size()) {
          throw std::runtime_error("CDA circuit exposes more input wires than expected");
        }
        clear_inputs[gate->out] = ordered_values[input_idx];
        shared_inputs[gate->out] = (pid == 0) ? ordered_values[input_idx] : Field(0);
        ++input_idx;
      }
    }
  }
  if (input_idx != ordered_values.size()) {
    throw std::runtime_error("CDA circuit input count does not match the expected 3 manual inputs");
  }

  const auto expected_outputs = cda_circuit.evaluate(clear_inputs);

  json output_data;
  output_data["details"] = {{"buy_list_size", buy_list_size},
                            {"sell_list_size", sell_list_size},
                            {"num_parties", nP},
                            {"pid", pid},
                            {"seed", seed},
                            {"repeat", repeat},
                            {"security_model", security_model_str},
                            {"lx", lx},
                            {"slack", slack},
                            {"new_order_name", new_order_name},
                            {"new_order_unit", new_order_unit},
                            {"new_order_price", new_order_price},
                            {"num_inputs", input_idx},
                            {"num_outputs", expected_outputs.size()}};
  output_data["expected_outputs"] = json::array();
  for (const auto& val : expected_outputs) {
    output_data["expected_outputs"].push_back(NTL::conv<uint64_t>(NTL::rep(val)));
  }
  output_data["benchmarks"] = json::array();

  for (size_t r = 0; r < repeat; ++r) {
    network->sync();
    StatsPoint offline_start(*network);
    StatsPoint offline_end(*network);
    json offline_bench;
    json online_bench;
    std::vector<Field> outputs;
    json output_delta_shares = json::array();

    if (security_model == asterisk2::SecurityModel::kSemiHonest) {
      asterisk2::SemiHonestAppEvaluator eval(static_cast<int>(nP), static_cast<int>(pid), network,
                                             level_circ, static_cast<int>(seed));
      auto offline_data = eval.offline(lx, slack);
      network->sync();
      offline_end = StatsPoint(*network);
      offline_bench = offline_end - offline_start;

      network->sync();
      StatsPoint online_start(*network);
      outputs = eval.onlineBatched(shared_inputs, offline_data);
      StatsPoint online_end(*network);
      online_bench = online_end - online_start;
    } else {
      asterisk2::MaliciousAppEvaluator eval(static_cast<int>(nP), static_cast<int>(pid), network,
                                            level_circ, static_cast<int>(seed));
      auto offline_data = eval.offline(lx, slack);
      network->sync();
      offline_end = StatsPoint(*network);
      offline_bench = offline_end - offline_start;

      network->sync();
      StatsPoint online_start(*network);
      outputs = eval.onlineBatched(shared_inputs, offline_data);
      StatsPoint online_end(*network);
      online_bench = online_end - online_start;

      for (const auto& out : eval.deltaOutputs()) {
        output_delta_shares.push_back((pid < nP) ? NTL::conv<uint64_t>(NTL::rep(out)) : 0);
      }
    }

    size_t offline_bytes = 0;
    for (const auto& val : offline_bench["communication"]) {
      offline_bytes += val.get<int64_t>();
    }
    size_t online_bytes = 0;
    for (const auto& val : online_bench["communication"]) {
      online_bytes += val.get<int64_t>();
    }

    json output_shares = json::array();
    for (const auto& out : outputs) {
      output_shares.push_back((pid < nP) ? NTL::conv<uint64_t>(NTL::rep(out)) : 0);
    }

    output_data["benchmarks"].push_back({
        {"offline", offline_bench},
        {"online", online_bench},
        {"offline_bytes", offline_bytes},
        {"online_bytes", online_bytes},
        {"output_shares", output_shares},
        {"output_delta_shares", output_delta_shares},
    });
  }

  if (opts.count("output") != 0) {
    saveJson(output_data, opts["output"].as<std::string>());
  }
}

bpo::options_description programOptions() {
  bpo::options_description desc("Asterisk2.0 Dark Pool CDA benchmark options");
  desc.add_options()
      ("buy-list-size,b", bpo::value<size_t>()->required(), "Buy list size.")
      ("sell-list-size,s", bpo::value<size_t>()->required(), "Sell list size.")
      ("num-parties,n", bpo::value<size_t>()->required(), "Number of computing parties.")
      ("pid,p", bpo::value<size_t>()->required(), "Party ID.")
      ("seed", bpo::value<size_t>()->default_value(200), "Value of the random seed.")
      ("repeat,r", bpo::value<size_t>()->default_value(1), "Number of repetitions.")
      ("security-model", bpo::value<std::string>()->default_value("semi-honest"),
       "Security model: semi-honest or malicious.")
      ("lx", bpo::value<size_t>()->default_value(16), "Comparison lx parameter.")
      ("slack", bpo::value<size_t>()->default_value(8), "Comparison slack parameter s.")
      ("new-order-name", bpo::value<int64_t>()->default_value(1),
       "Manual input for the new order name wire.")
      ("new-order-unit", bpo::value<int64_t>()->default_value(1),
       "Manual input for the new order unit wire.")
      ("new-order-price", bpo::value<int64_t>()->default_value(1),
       "Manual input for the new order price wire.")
      ("localhost", bpo::bool_switch(), "All parties are on same machine.")
      ("port", bpo::value<int>()->default_value(10000), "Base port for networking.")
      ("output,o", bpo::value<std::string>(), "File to save benchmarks.");
  return desc;
}

int main(int argc, char* argv[]) {
  ZZ_p::init(conv<ZZ>(common::utils::kFieldPrimeDecimal));

  auto prog_opts(programOptions());
  bpo::options_description cmdline("Benchmark Asterisk2.0 Dark Pool CDA.");
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
