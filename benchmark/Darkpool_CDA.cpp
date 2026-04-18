#include <io/netmp.h>
#include <asterisk/offline_evaluator.h>
#include <asterisk/online_evaluator.h>
#include <utils/circuit.h>
#include <utils/darkpool.h>

#include <algorithm>
#include <boost/program_options.hpp>
#include <cmath>
#include <iostream>
#include <memory>

#include "utils.h"

using namespace asterisk;
using json = nlohmann::json;
namespace bpo = boost::program_options;

void benchmark(const bpo::variables_map& opts) {
    bool save_output = false;
    std::string save_file;
    if (opts.count("output") != 0) {
        save_output = true;
        save_file = opts["output"].as<std::string>();
    }

    auto buy_list_size = opts["buy-list-size"].as<size_t>();
    auto sell_list_size = opts["sell-list-size"].as<size_t>();
    auto nP = opts["num-parties"].as<size_t>();
    auto pid = opts["pid"].as<size_t>();
    auto security_param = opts["security-param"].as<size_t>();
    auto threads = opts["threads"].as<size_t>();
    auto seed = opts["seed"].as<size_t>();
    auto repeat = opts["repeat"].as<size_t>();
    auto port = opts["port"].as<int>();
    auto new_order_name = opts["new-order-name"].as<int64_t>();
    auto new_order_unit = opts["new-order-unit"].as<int64_t>();
    auto new_order_price = opts["new-order-price"].as<int64_t>();

    std::shared_ptr<io::NetIOMP> network = nullptr;
    if (opts["localhost"].as<bool>()) {
        network = std::make_shared<io::NetIOMP>(pid, nP+1, port, nullptr, true);
    }
    else {
        std::ifstream fnet(opts["net-config"].as<std::string>());
        if (!fnet.good()) {
        fnet.close();
        throw std::runtime_error("Could not open network config file");
        }
        json netdata;
        fnet >> netdata;
        fnet.close();

        std::vector<std::string> ipaddress(nP+1);
        std::array<char*, 5> ip{};
        for (size_t i = 0; i < nP+1; ++i) {
            ipaddress[i] = netdata[i].get<std::string>();
            ip[i] = ipaddress[i].data();
        }

        network = std::make_shared<io::NetIOMP>(pid, nP+1, port, ip.data(), false);
    }
    std::cerr << "BOUND_OK pid=" << pid << " port=" << port << std::endl;

    json output_data;
    output_data["details"] = {{"buy_list_size", buy_list_size},
                                {"sell_list_size", sell_list_size},
                                {"num-parties", nP},
                                {"pid", pid},
                                {"security_param", security_param},
                                {"threads", threads},
                                {"seed", seed},
                                {"repeat", repeat},
                                {"new_order_name", new_order_name},
                                {"new_order_unit", new_order_unit},
                                {"new_order_price", new_order_price}};
    output_data["benchmarks"] = json::array();

    std::cout << "--- Details ---\n";
    for (const auto& [key, value] : output_data["details"].items()) {
        std::cout << key << ": " << value << "\n";
    }
    std::cout << std::endl;

    size_t N = sell_list_size;
    size_t M = buy_list_size;
    
    common::utils::DarkPool<Field> darkpool_ob(N,M);
    darkpool_ob.resizeList();
    auto CDA_circ = darkpool_ob.getCDACircuit().orderGatesByLevel();
    
    std::cout << "--- Circuit ---\n";
    std::cout << CDA_circ << std::endl;


    std::unordered_map<common::utils::wire_t, int> input_pid_map;
    std::unordered_map<common::utils::wire_t, Field> input_map;

    std::vector<Field> ordered_values = {
        Field(new_order_name),
        Field(new_order_unit),
        Field(new_order_price),
    };
    size_t input_idx = 0;
    for (const auto& level : CDA_circ.gates_by_level) {
        for (const auto& g : level) {
            if (g->type == common::utils::GateType::kInp) {
                if (input_idx >= ordered_values.size()) {
                    throw std::runtime_error("CDA circuit exposes more input wires than expected");
                }
                input_pid_map[g->out] = 1;
                input_map[g->out] = ordered_values[input_idx];
                ++input_idx;
            }
        }
    }
    if (input_idx != ordered_values.size()) {
        throw std::runtime_error("CDA circuit input count does not match the expected 3 manual inputs");
    }

    for (size_t r = 0; r < repeat; ++r) {
        
        network->sync();
        StatsPoint offline_start(*network);
        // Offline 
        OfflineEvaluator CDA_off_eval(nP, pid, network, CDA_circ, security_param, threads, seed);
        auto CDA_preproc = CDA_off_eval.run(input_pid_map);
        StatsPoint offline_end(*network);
        network->sync();

        // Online
        StatsPoint online_start(*network);
        OnlineEvaluator CDA_eval(nP, pid, network, std::move(CDA_preproc), CDA_circ, 
                                                                  security_param, threads, seed);
        (void)CDA_eval.evaluateCircuit(input_map);
        StatsPoint online_end(*network);

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
        output_data["benchmarks"].push_back({
            {"offline", offline_bench},
            {"online", online_bench},
            {"offline_bytes", offline_bytes},
            {"online_bytes", online_bytes},
        });

        std::cout << "--- Repetition " << r + 1 << " ---\n";
        std::cout << "offline time: " << offline_bench["time"] << " ms\n";
        std::cout << "offline sent: " << offline_bytes << " bytes\n";
        std::cout << "online time: " << online_bench["time"] << " ms\n";
        std::cout << "online sent: " << online_bytes << " bytes\n";

        std::cout << std::endl;
    }

    if (save_output) {
        saveJson(output_data, save_file);
    }

}

// clang-format off
bpo::options_description programOptions() {
    bpo::options_description desc("Following options are supported by config file too.");
    desc.add_options()
        ("buy-list-size,b", bpo::value<size_t>()->required(), "Buy list size.")
        ("sell-list-size,s", bpo::value<size_t>()->required(), "Sell list size.")
        ("num-parties,n", bpo::value<size_t>()->required(), "Number of parties.")
        ("pid,p", bpo::value<size_t>()->required(), "Party ID.")
        ("security-param", bpo::value<size_t>()->default_value(128), "Security parameter in bits.")
        ("threads,t", bpo::value<size_t>()->default_value(1), "Number of threads (recommended 6).")
        ("seed", bpo::value<size_t>()->default_value(200), "Value of the random seed.")
        ("new-order-name", bpo::value<int64_t>()->default_value(1),
         "Deterministic value for the new order name wire.")
        ("new-order-unit", bpo::value<int64_t>()->default_value(1),
         "Deterministic value for the new order unit wire.")
        ("new-order-price", bpo::value<int64_t>()->default_value(1),
         "Deterministic value for the new order price wire.")
        ("net-config", bpo::value<std::string>(), "Path to JSON file containing network details of all parties.")
        ("localhost", bpo::bool_switch(), "All parties are on same machine.")
        ("port", bpo::value<int>()->default_value(10000), "Base port for networking.")
        ("output,o", bpo::value<std::string>(), "File to save benchmarks.")
        ("repeat,r", bpo::value<size_t>()->default_value(1), "Number of times to run benchmarks.");

  return desc;
}
// clang-format on

int main(int argc, char* argv[]) {
    ZZ_p::init(conv<ZZ>("18446744073709551557"));
    auto prog_opts(programOptions());

    bpo::options_description cmdline(
      "Benchmark online phase for multiplication gates.");
    cmdline.add(prog_opts);
    cmdline.add_options()(
      "config,c", bpo::value<std::string>(),
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

        // Check if output file already exists.
        /*if (opts.count("output") != 0) {
            std::ifstream ftemp(opts["output"].as<std::string>());
            if (ftemp.good()) {
                ftemp.close();
                throw std::runtime_error("Output file aready exists.");
            }
            ftemp.close();
        }*/

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
