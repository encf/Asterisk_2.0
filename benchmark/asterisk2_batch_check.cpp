#include <io/netmp.h>
#include <utils/circuit.h>
#include <utils/darkpool.h>

#include <boost/program_options.hpp>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "Asterisk2.0/app_evaluator.h"

using common::utils::Field;
using common::utils::GateType;
using common::utils::LevelOrderedCircuit;
using common::utils::wire_t;
namespace bpo = boost::program_options;

namespace {

LevelOrderedCircuit buildSingleMulCircuit() {
  common::utils::Circuit<Field> circ;
  auto in1 = circ.newInputWire();
  auto in2 = circ.newInputWire();
  auto out = circ.addGate(GateType::kMul, in1, in2);
  circ.setAsOutput(out);
  return circ.orderGatesByLevel();
}

LevelOrderedCircuit buildEmptyCircuit() {
  common::utils::Circuit<Field> circ;
  return circ.orderGatesByLevel();
}

struct InputCircuitData {
  LevelOrderedCircuit circ;
  std::vector<wire_t> inputs;
};

InputCircuitData buildInputCircuit(size_t num_inputs) {
  common::utils::Circuit<Field> circ;
  std::vector<wire_t> inputs;
  inputs.reserve(num_inputs);
  for (size_t i = 0; i < num_inputs; ++i) {
    auto w = circ.newInputWire();
    inputs.push_back(w);
    circ.setAsOutput(w);
  }
  return {circ.orderGatesByLevel(), inputs};
}

void checkFieldEq(const std::string& label, size_t idx, const Field& lhs, const Field& rhs) {
  if (lhs != rhs) {
    throw std::runtime_error(
        label + " mismatch at index " + std::to_string(idx) + ": lhs=" +
        std::to_string(NTL::conv<long>(NTL::rep(lhs))) + ", rhs=" +
        std::to_string(NTL::conv<long>(NTL::rep(rhs))));
  }
}

void checkFieldVecEq(const std::string& label, const std::vector<Field>& lhs,
                     const std::vector<Field>& rhs) {
  if (lhs.size() != rhs.size()) {
    throw std::runtime_error(label + " size mismatch");
  }
  for (size_t i = 0; i < lhs.size(); ++i) {
    checkFieldEq(label, i, lhs[i], rhs[i]);
  }
}

void runSemiHonestChecks(const bpo::variables_map& opts,
                         const std::shared_ptr<io::NetIOMP>& network) {
  const int nP = static_cast<int>(opts["num-parties"].as<size_t>());
  const int pid = static_cast<int>(opts["pid"].as<size_t>());
  const int port = opts["port"].as<int>();
  const int seed = static_cast<int>(opts["seed"].as<size_t>());
  const size_t lx = opts["lx"].as<size_t>();
  const size_t slack = opts["slack"].as<size_t>();
  const size_t batch_size = opts["batch-size"].as<size_t>();
  const size_t cda_size = opts["cda-size"].as<size_t>();

  (void)port;

  const auto mul_circ = buildSingleMulCircuit();
  const auto empty_circ = buildEmptyCircuit();

  std::vector<Field> mul_x;
  std::vector<Field> mul_y;
  std::vector<asterisk2::MulOfflineData> mul_off(batch_size);
  mul_x.reserve(batch_size);
  mul_y.reserve(batch_size);
  for (size_t i = 0; i < batch_size; ++i) {
    mul_x.push_back(Field(static_cast<long>(2 + i)));
    mul_y.push_back(Field(static_cast<long>(5 + 2 * i)));
    asterisk2::Protocol mul_off_proto(nP, pid, network, mul_circ, seed + static_cast<int>(17 * i));
    mul_off[i] = mul_off_proto.mul_offline();
  }

  network->sync();
  std::vector<Field> mul_scalar;
  mul_scalar.reserve(batch_size);
  for (size_t i = 0; i < batch_size; ++i) {
    asterisk2::Protocol mul_scalar_proto(nP, pid, network, mul_circ,
                                         seed + static_cast<int>(100 + i));
    std::unordered_map<wire_t, Field> inputs = {{0, mul_x[i]}, {1, mul_y[i]}};
    auto out = mul_scalar_proto.mul_online(inputs, mul_off[i]);
    mul_scalar.push_back((pid < nP && !out.empty()) ? out[0] : Field(0));
  }

  network->sync();
  asterisk2::Protocol mul_batch_proto(nP, pid, network, mul_circ, seed + 500);
  std::vector<const asterisk2::MulOfflineData*> mul_off_ptrs;
  mul_off_ptrs.reserve(batch_size);
  for (const auto& off : mul_off) {
    mul_off_ptrs.push_back(&off);
  }
  auto mul_batch = mul_batch_proto.mul_online_semi_honest_batch(mul_x, mul_y, mul_off_ptrs);
  if (pid < nP) {
    checkFieldVecEq("semi-honest mul batch", mul_scalar, mul_batch);
  }

  std::vector<Field> cmp_x;
  std::vector<asterisk2::CompareOfflineData> cmp_off(batch_size);
  cmp_x.reserve(batch_size);
  for (size_t i = 0; i < batch_size; ++i) {
    const long raw = static_cast<long>(i) - static_cast<long>(batch_size / 2);
    cmp_x.push_back(Field(raw));
    asterisk2::Protocol cmp_off_proto(nP, pid, network, empty_circ, seed + static_cast<int>(200 + i));
    cmp_off[i] = cmp_off_proto.compare_offline_tagged(lx, slack, 1000 + i);
  }

  network->sync();
  std::vector<Field> cmp_scalar;
  cmp_scalar.reserve(batch_size);
  for (size_t i = 0; i < batch_size; ++i) {
    asterisk2::Protocol cmp_scalar_proto(nP, pid, network, empty_circ, seed + 300);
    cmp_scalar.push_back(cmp_scalar_proto.compare_online(cmp_x[i], cmp_off[i]));
  }

  network->sync();
  asterisk2::Protocol cmp_batch_proto(nP, pid, network, empty_circ, seed + 300);
  std::vector<const asterisk2::CompareOfflineData*> cmp_off_ptrs;
  cmp_off_ptrs.reserve(batch_size);
  for (const auto& off : cmp_off) {
    cmp_off_ptrs.push_back(&off);
  }
  auto cmp_batch = cmp_batch_proto.compare_online_batch(cmp_x, cmp_off_ptrs);
  checkFieldVecEq("semi-honest compare batch", cmp_scalar, cmp_batch);

  std::vector<Field> eqz_x = {Field(0), Field(1), Field(-1), Field(3)};
  if (eqz_x.size() > batch_size) {
    eqz_x.resize(batch_size);
  }
  while (eqz_x.size() < batch_size) {
    eqz_x.push_back(Field(static_cast<long>(eqz_x.size() + 2)));
  }
  std::vector<asterisk2::EqzOfflineData> eqz_off(batch_size);
  for (size_t i = 0; i < batch_size; ++i) {
    asterisk2::Protocol eqz_off_proto(nP, pid, network, empty_circ, seed + static_cast<int>(400 + i));
    eqz_off[i] = eqz_off_proto.eqz_offline_tagged(lx, slack, 2000 + i);
  }

  network->sync();
  std::vector<Field> eqz_scalar;
  eqz_scalar.reserve(batch_size);
  for (size_t i = 0; i < batch_size; ++i) {
    asterisk2::Protocol eqz_scalar_proto(nP, pid, network, empty_circ, seed + 500);
    eqz_scalar.push_back(eqz_scalar_proto.eqz_online(eqz_x[i], eqz_off[i]));
  }

  network->sync();
  asterisk2::Protocol eqz_batch_proto(nP, pid, network, empty_circ, seed + 500);
  std::vector<const asterisk2::EqzOfflineData*> eqz_off_ptrs;
  eqz_off_ptrs.reserve(batch_size);
  for (const auto& off : eqz_off) {
    eqz_off_ptrs.push_back(&off);
  }
  auto eqz_batch = eqz_batch_proto.eqz_online_batch(eqz_x, eqz_off_ptrs);
  checkFieldVecEq("semi-honest eqz batch", eqz_scalar, eqz_batch);

  common::utils::DarkPool<Field> darkpool(cda_size, cda_size);
  darkpool.resizeList();
  auto cda_circ = darkpool.getCDACircuit().orderGatesByLevel();
  std::unordered_map<wire_t, Field> inputs;
  std::vector<Field> ordered_values = {Field(1), Field(2), Field(3)};
  size_t input_idx = 0;
  for (const auto& level : cda_circ.gates_by_level) {
    for (const auto& gate : level) {
      if (gate->type == GateType::kInp) {
        inputs[gate->out] = (pid == 0) ? ordered_values[input_idx] : Field(0);
        ++input_idx;
      }
    }
  }

  asterisk2::SemiHonestAppEvaluator eval_scalar(nP, pid, network, cda_circ, seed + 1000);
  auto app_offline = eval_scalar.offline(lx, slack);
  network->sync();
  auto cda_scalar = eval_scalar.online(inputs, app_offline);
  network->sync();
  auto cda_batch = eval_scalar.onlineBatched(inputs, app_offline);
  checkFieldVecEq("semi-honest CDA evaluator batch", cda_scalar, cda_batch);
}

void runMaliciousChecks(const bpo::variables_map& opts,
                        const std::shared_ptr<io::NetIOMP>& network) {
  const int nP = static_cast<int>(opts["num-parties"].as<size_t>());
  const int pid = static_cast<int>(opts["pid"].as<size_t>());
  const int seed = static_cast<int>(opts["seed"].as<size_t>());
  const size_t lx = opts["lx"].as<size_t>();
  const size_t slack = opts["slack"].as<size_t>();
  const size_t batch_size = opts["batch-size"].as<size_t>();
  const size_t cda_size = opts["cda-size"].as<size_t>();

  asterisk2::ProtocolConfig cfg;
  cfg.security_model = asterisk2::SecurityModel::kMalicious;

  const auto mul_circ = buildSingleMulCircuit();
  const auto empty_circ = buildEmptyCircuit();

  {
    const int block_seed = seed + 100;
    auto input_circ = buildInputCircuit(2 * batch_size);
    asterisk2::Protocol input_proto(nP, pid, network, input_circ.circ, block_seed, cfg);
    asterisk2::Protocol auth_proto(nP, pid, network, mul_circ, block_seed, cfg);
    auto input_auth = auth_proto.mul_offline();

    std::unordered_map<wire_t, Field> clear_inputs;
    for (size_t i = 0; i < batch_size; ++i) {
      clear_inputs[input_circ.inputs[i]] = Field(static_cast<long>(2 + i));
      clear_inputs[input_circ.inputs[batch_size + i]] = Field(static_cast<long>(7 + i));
    }
    auto shared = input_proto.maliciousInputShareForTesting(clear_inputs, input_auth);

    std::vector<asterisk2::MulOfflineData> mul_off(batch_size);
    for (size_t i = 0; i < batch_size; ++i) {
      asterisk2::Protocol off_proto(nP, pid, network, mul_circ, block_seed, cfg);
      mul_off[i] = off_proto.mul_offline();
    }

    network->sync();
    std::vector<asterisk2::AuthMulResult> scalar(batch_size);
    for (size_t i = 0; i < batch_size; ++i) {
      asterisk2::Protocol scalar_proto(nP, pid, network, mul_circ, block_seed, cfg);
      const Field x_share =
          (pid < nP) ? shared.x_shares.at(input_circ.inputs[i]) : Field(0);
      const Field dx_share =
          (pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[i]) : Field(0);
      const Field y_share =
          (pid < nP) ? shared.x_shares.at(input_circ.inputs[batch_size + i]) : Field(0);
      const Field dy_share =
          (pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[batch_size + i]) : Field(0);
      scalar[i] = scalar_proto.mul_online_malicious_single(
          x_share, dx_share, y_share, dy_share, mul_off[i]);
    }

    network->sync();
    asterisk2::Protocol batch_proto(nP, pid, network, mul_circ, block_seed, cfg);
    std::vector<Field> x_shares;
    std::vector<Field> dx_shares;
    std::vector<Field> y_shares;
    std::vector<Field> dy_shares;
    std::vector<const asterisk2::MulOfflineData*> off_ptrs;
    for (size_t i = 0; i < batch_size; ++i) {
      x_shares.push_back((pid < nP) ? shared.x_shares.at(input_circ.inputs[i]) : Field(0));
      dx_shares.push_back((pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[i]) : Field(0));
      y_shares.push_back((pid < nP) ? shared.x_shares.at(input_circ.inputs[batch_size + i])
                                    : Field(0));
      dy_shares.push_back((pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[batch_size + i])
                                     : Field(0));
      off_ptrs.push_back(&mul_off[i]);
    }
    auto batch = batch_proto.mul_online_malicious_batch(x_shares, dx_shares, y_shares, dy_shares,
                                                        off_ptrs);
    for (size_t i = 0; i < batch_size; ++i) {
      checkFieldEq("malicious mul batch share", i, scalar[i].share, batch[i].share);
      checkFieldEq("malicious mul batch delta", i, scalar[i].delta_share, batch[i].delta_share);
    }
  }

  {
    const int block_seed = seed + 200;
    auto input_circ = buildInputCircuit(batch_size);
    asterisk2::Protocol input_proto(nP, pid, network, input_circ.circ, block_seed, cfg);
    asterisk2::Protocol auth_proto(nP, pid, network, mul_circ, block_seed, cfg);
    auto input_auth = auth_proto.mul_offline();

    std::unordered_map<wire_t, Field> clear_inputs;
    for (size_t i = 0; i < batch_size; ++i) {
      clear_inputs[input_circ.inputs[i]] = Field(static_cast<long>(i) - static_cast<long>(batch_size / 2));
    }
    auto shared = input_proto.maliciousInputShareForTesting(clear_inputs, input_auth);

    std::vector<asterisk2::CompareOfflineDataMalicious> cmp_off(batch_size);
    for (size_t i = 0; i < batch_size; ++i) {
      asterisk2::Protocol off_proto(nP, pid, network, empty_circ, block_seed, cfg);
      cmp_off[i] = off_proto.compare_offline_malicious_tagged(lx, slack, 3000 + i);
    }

    network->sync();
    std::vector<asterisk2::AuthCompareResult> scalar(batch_size);
    for (size_t i = 0; i < batch_size; ++i) {
      asterisk2::Protocol scalar_proto(nP, pid, network, empty_circ, block_seed, cfg);
      const Field x_share =
          (pid < nP) ? shared.x_shares.at(input_circ.inputs[i]) : Field(0);
      const Field dx_share =
          (pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[i]) : Field(0);
      scalar[i] = scalar_proto.compare_online_malicious(
          x_share, dx_share, cmp_off[i]);
    }

    network->sync();
    asterisk2::Protocol batch_proto(nP, pid, network, empty_circ, block_seed, cfg);
    std::vector<Field> x_shares;
    std::vector<Field> dx_shares;
    std::vector<const asterisk2::CompareOfflineDataMalicious*> off_ptrs;
    for (size_t i = 0; i < batch_size; ++i) {
      x_shares.push_back((pid < nP) ? shared.x_shares.at(input_circ.inputs[i]) : Field(0));
      dx_shares.push_back((pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[i]) : Field(0));
      off_ptrs.push_back(&cmp_off[i]);
    }
    auto batch = batch_proto.compare_online_malicious_batch(x_shares, dx_shares, off_ptrs);
    for (size_t i = 0; i < batch_size; ++i) {
      checkFieldEq("malicious compare batch share", i, scalar[i].gtez_share, batch[i].gtez_share);
      checkFieldEq("malicious compare batch delta", i, scalar[i].delta_gtez_share,
                   batch[i].delta_gtez_share);
    }
  }

  {
    const int block_seed = seed + 300;
    auto input_circ = buildInputCircuit(batch_size);
    asterisk2::Protocol input_proto(nP, pid, network, input_circ.circ, block_seed, cfg);
    asterisk2::Protocol auth_proto(nP, pid, network, mul_circ, block_seed, cfg);
    auto input_auth = auth_proto.mul_offline();

    std::unordered_map<wire_t, Field> clear_inputs;
    for (size_t i = 0; i < batch_size; ++i) {
      clear_inputs[input_circ.inputs[i]] = (i == 0) ? Field(0) : Field(static_cast<long>(i));
    }
    auto shared = input_proto.maliciousInputShareForTesting(clear_inputs, input_auth);

    std::vector<asterisk2::EqzOfflineDataMalicious> eqz_off(batch_size);
    for (size_t i = 0; i < batch_size; ++i) {
      asterisk2::Protocol off_proto(nP, pid, network, empty_circ, block_seed, cfg);
      eqz_off[i] = off_proto.eqz_offline_malicious_tagged(lx, slack, 4000 + i);
    }

    network->sync();
    std::vector<asterisk2::AuthEqzResult> scalar(batch_size);
    for (size_t i = 0; i < batch_size; ++i) {
      asterisk2::Protocol scalar_proto(nP, pid, network, empty_circ, block_seed, cfg);
      const Field x_share =
          (pid < nP) ? shared.x_shares.at(input_circ.inputs[i]) : Field(0);
      const Field dx_share =
          (pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[i]) : Field(0);
      scalar[i] = scalar_proto.eqz_online_malicious(
          x_share, dx_share, eqz_off[i]);
    }

    network->sync();
    asterisk2::Protocol batch_proto(nP, pid, network, empty_circ, block_seed, cfg);
    std::vector<Field> x_shares;
    std::vector<Field> dx_shares;
    std::vector<const asterisk2::EqzOfflineDataMalicious*> off_ptrs;
    for (size_t i = 0; i < batch_size; ++i) {
      x_shares.push_back((pid < nP) ? shared.x_shares.at(input_circ.inputs[i]) : Field(0));
      dx_shares.push_back((pid < nP) ? shared.delta_x_shares.at(input_circ.inputs[i]) : Field(0));
      off_ptrs.push_back(&eqz_off[i]);
    }
    auto batch = batch_proto.eqz_online_malicious_batch(x_shares, dx_shares, off_ptrs);
    for (size_t i = 0; i < batch_size; ++i) {
      checkFieldEq("malicious eqz batch share", i, scalar[i].eqz_share, batch[i].eqz_share);
      checkFieldEq("malicious eqz batch delta", i, scalar[i].delta_eqz_share,
                   batch[i].delta_eqz_share);
    }
  }

  common::utils::DarkPool<Field> darkpool(cda_size, cda_size);
  darkpool.resizeList();
  auto cda_circ = darkpool.getCDACircuit().orderGatesByLevel();
  std::unordered_map<wire_t, Field> inputs;
  std::vector<Field> ordered_values = {Field(1), Field(2), Field(3)};
  size_t input_idx = 0;
  for (const auto& level : cda_circ.gates_by_level) {
    for (const auto& gate : level) {
      if (gate->type == GateType::kInp) {
        inputs[gate->out] = (pid == 0) ? ordered_values[input_idx] : Field(0);
        ++input_idx;
      }
    }
  }

  asterisk2::MaliciousAppEvaluator eval_scalar(nP, pid, network, cda_circ, seed + 1000);
  auto app_offline = eval_scalar.offline(lx, slack);
  network->sync();
  auto cda_scalar = eval_scalar.online(inputs, app_offline);
  auto cda_scalar_delta = eval_scalar.deltaOutputs();
  network->sync();
  auto cda_batch = eval_scalar.onlineBatched(inputs, app_offline);
  auto cda_batch_delta = eval_scalar.deltaOutputs();
  checkFieldVecEq("malicious CDA evaluator batch", cda_scalar, cda_batch);
  checkFieldVecEq("malicious CDA evaluator delta batch", cda_scalar_delta, cda_batch_delta);
}

bpo::options_description programOptions() {
  bpo::options_description desc("Asterisk2.0 batch correctness check options");
  desc.add_options()
      ("num-parties,n", bpo::value<size_t>()->required(), "Number of computing parties.")
      ("pid,p", bpo::value<size_t>()->required(), "Party ID.")
      ("seed", bpo::value<size_t>()->default_value(200), "Random seed.")
      ("security-model", bpo::value<std::string>()->default_value("semi-honest"),
       "Security model: semi-honest or malicious.")
      ("lx", bpo::value<size_t>()->default_value(16), "Comparison lx parameter.")
      ("slack", bpo::value<size_t>()->default_value(8), "Comparison slack parameter.")
      ("batch-size", bpo::value<size_t>()->default_value(4), "How many independent gates to batch.")
      ("cda-size", bpo::value<size_t>()->default_value(4), "CDA buy/sell list size for evaluator check.")
      ("localhost", bpo::bool_switch(), "All parties are on same machine.")
      ("port", bpo::value<int>()->default_value(10000), "Base port for networking.");
  return desc;
}

}  // namespace

int main(int argc, char* argv[]) {
  ZZ_p::init(conv<ZZ>(common::utils::kFieldPrimeDecimal));

  auto prog_opts(programOptions());
  bpo::options_description cmdline("Benchmark Asterisk2.0 batched protocol correctness.");
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
    if (!opts["localhost"].as<bool>()) {
      throw std::runtime_error("Asterisk2.0 batch check currently supports localhost only");
    }

    const auto nP = static_cast<int>(opts["num-parties"].as<size_t>());
    const auto pid = static_cast<int>(opts["pid"].as<size_t>());
    const auto port = opts["port"].as<int>();
    const auto security_model = opts["security-model"].as<std::string>();
    auto network = std::make_shared<io::NetIOMP>(pid, nP + 1, port, nullptr, true);

    if (security_model == "semi-honest") {
      runSemiHonestChecks(opts, network);
    } else if (security_model == "malicious") {
      runMaliciousChecks(opts, network);
    } else {
      throw std::runtime_error("Unsupported security-model, expected semi-honest or malicious");
    }

    network->sync();
    if (pid == 0) {
      std::cout << "Batch correctness checks passed for " << security_model << std::endl;
    }
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << "\nFatal error" << std::endl;
    return 1;
  }

  return 0;
}
