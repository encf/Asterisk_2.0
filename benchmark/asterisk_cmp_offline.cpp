#include <io/netmp.h>
#include <asterisk/offline_evaluator.h>
#include <utils/circuit.h>

#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_map>

#include "utils.h"

using namespace asterisk;
using json = nlohmann::json;
namespace bpo = boost::program_options;

namespace {

common::utils::Circuit<Field> generateCompareCircuit(size_t compare_count) {
  common::utils::Circuit<Field> circ;
  for (size_t i = 0; i < compare_count; ++i) {
    auto in = circ.newInputWire();
    auto out = circ.addGate(common::utils::GateType::kLtz, in);
    circ.setAsOutput(out);
  }
  return circ;
}

std::shared_ptr<io::NetIOMP> makeNetwork(const bpo::variables_map& opts, size_t pid, size_t nP,
                                         int port) {
  if (opts["localhost"].as<bool>()) {
    return std::make_shared<io::NetIOMP>(pid, nP + 1, port, nullptr, true);
  }

  std::ifstream fnet(opts["net-config"].as<std::string>());
  if (!fnet.good()) {
    fnet.close();
    throw std::runtime_error("Could not open network config file");
  }
  json netdata;
  fnet >> netdata;
  fnet.close();

  std::vector<std::string> ipaddress(nP + 1);
  std::vector<char*> ip(nP + 1, nullptr);
  for (size_t i = 0; i < nP + 1; ++i) {
    ipaddress[i] = netdata[i].get<std::string>();
    ip[i] = ipaddress[i].data();
  }
  return std::make_shared<io::NetIOMP>(pid, nP + 1, port, ip.data(), false);
}

}  // namespace

void benchmark(const bpo::variables_map& opts) {
  bool save_output = false;
  std::string save_file;
  if (opts.count("output") != 0) {
    save_output = true;
    save_file = opts["output"].as<std::string>();
  }

  const auto compare_count = opts["compare-count"].as<size_t>();
  const auto nP = opts["num-parties"].as<size_t>();
  const auto pid = opts["pid"].as<size_t>();
  const auto security_param = opts["security-param"].as<size_t>();
  const auto threads = opts["threads"].as<size_t>();
  const auto seed = opts["seed"].as<size_t>();
  const auto repeat = opts["repeat"].as<size_t>();
  const auto port = opts["port"].as<int>();

  auto network = makeNetwork(opts, pid, nP, port);
  std::cerr << "BOUND_OK pid=" << pid << " port=" << port << std::endl;

  json output_data;
  output_data["details"] = {{"compare_count", compare_count},
                            {"num-parties", nP},
                            {"pid", pid},
                            {"security_param", security_param},
                            {"threads", threads},
                            {"seed", seed},
                            {"repeat", repeat}};
  output_data["benchmarks"] = json::array();

  auto circ = generateCompareCircuit(compare_count).orderGatesByLevel();

  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  for (const auto& g : circ.gates_by_level[0]) {
    if (g->type == common::utils::GateType::kInp) {
      input_pid_map[g->out] = 1;
    }
  }

  for (size_t r = 0; r < repeat; ++r) {
    OfflineEvaluator off_eval(nP, pid, network, circ, security_param, threads, seed);
    network->sync();
    StatsPoint start(*network);
    auto preproc = off_eval.run(input_pid_map);
    (void)preproc;
    StatsPoint end(*network);

    auto rbench = end - start;
    output_data["benchmarks"].push_back(rbench);
  }

  output_data["stats"] = {{"peak_virtual_memory", peakVirtualMemory()},
                          {"peak_resident_set_size", peakResidentSetSize()}};

  if (save_output) {
    saveJson(output_data, save_file);
  }
}

bpo::options_description programOptions() {
  bpo::options_description desc("Asterisk legacy comparison offline benchmark options");
  desc.add_options()
      ("compare-count,c", bpo::value<size_t>()->required(), "Number of LTZ comparisons.")
      ("num-parties,n", bpo::value<size_t>()->required(), "Number of parties.")
      ("pid,p", bpo::value<size_t>()->required(), "Party ID.")
      ("security-param", bpo::value<size_t>()->default_value(128), "Security parameter in bits.")
      ("threads,t", bpo::value<size_t>()->default_value(6), "Number of threads.")
      ("seed", bpo::value<size_t>()->default_value(200), "Value of the random seed.")
      ("net-config", bpo::value<std::string>(), "Path to JSON file containing network details.")
      ("localhost", bpo::bool_switch(), "All parties are on same machine.")
      ("port", bpo::value<int>()->default_value(10000), "Base port for networking.")
      ("output,o", bpo::value<std::string>(), "File to save benchmarks.")
      ("repeat,r", bpo::value<size_t>()->default_value(1), "Number of times to run benchmarks.");
  return desc;
}

int main(int argc, char* argv[]) {
  ZZ_p::init(conv<ZZ>("18446744073709551557"));
  auto prog_opts(programOptions());

  bpo::options_description cmdline("Benchmark legacy Asterisk comparison offline phase.");
  cmdline.add(prog_opts);
  cmdline.add_options()("config,cfg", bpo::value<std::string>(),
                        "configuration file for easy specification of cmd line arguments")(
      "help,h", "produce help message");

  bpo::variables_map opts;
  bpo::store(bpo::command_line_parser(argc, argv).options(cmdline).run(), opts);

  if (opts.count("help") != 0) {
    std::cout << cmdline << std::endl;
    return 0;
  }

  if (opts.count("config") > 0) {
    std::string cpath(opts["config"].as<std::string>());
    std::ifstream fin(cpath.c_str());
    if (fin.fail()) {
      std::cerr << "Could not open configuration file at " << cpath << "\n";
      return 1;
    }
    bpo::store(bpo::parse_config_file(fin, prog_opts), opts);
  }

  try {
    bpo::notify(opts);
    if (!opts["localhost"].as<bool>() && (opts.count("net-config") == 0)) {
      throw std::runtime_error("Expected one of 'localhost' or 'net-config'");
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
