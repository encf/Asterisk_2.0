#pragma once

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace common::utils {

struct NetworkCostModel {
  uint64_t bandwidth_bps{0};
  double latency_ms{0.0};
};

inline NetworkCostModel presetNetworkCostModel(const std::string& preset) {
  if (preset == "lan") {
    return NetworkCostModel{1'000'000'000ULL, 1.0};
  }
  if (preset == "wan") {
    return NetworkCostModel{100'000'000ULL, 20.0};
  }
  if (preset == "none" || preset.empty()) {
    return NetworkCostModel{};
  }
  throw std::runtime_error("Unsupported net-preset, expected none|lan|wan");
}

inline NetworkCostModel resolveNetworkCostModel(const std::string& preset,
                                                uint64_t bandwidth_bps,
                                                double latency_ms) {
  auto model = presetNetworkCostModel(preset);
  if (bandwidth_bps > 0) {
    model.bandwidth_bps = bandwidth_bps;
  }
  if (latency_ms > 0) {
    model.latency_ms = latency_ms;
  }
  return model;
}

inline bool isNetworkCostModelEnabled(const NetworkCostModel& model) {
  return model.bandwidth_bps > 0;
}

// Simplified communication model:
//   round_time = propagation delay + transmission delay
//              = latency_ms + (bytes_sent * 8) * 1000 / bandwidth_bps
// Ignores queueing delay, retransmission, packetization and protocol overhead.
inline double estimateRoundTimeMs(size_t bytes_sent, const NetworkCostModel& model) {
  if (!isNetworkCostModelEnabled(model)) {
    return 0.0;
  }
  const double tx_ms = (static_cast<double>(bytes_sent) * 8.0 * 1000.0) /
                       static_cast<double>(model.bandwidth_bps);
  return model.latency_ms + tx_ms;
}

// All-to-all variant where one party sends msg_size_bytes to each of (n-1) peers
// and total outgoing bandwidth is shared:
//   round_time = latency_ms + (msg_size_bytes * (n - 1) * 8) * 1000 / bandwidth_bps
// Same simplified assumptions as above.
inline double estimateAllToAllRoundTimeMs(size_t msg_size_bytes, size_t parties,
                                          const NetworkCostModel& model) {
  if (!isNetworkCostModelEnabled(model)) {
    return 0.0;
  }
  if (parties < 2) {
    return model.latency_ms;
  }
  const size_t total_outgoing_bytes = msg_size_bytes * (parties - 1);
  return estimateRoundTimeMs(total_outgoing_bytes, model);
}

inline double estimateTotalTimeMs(double per_round_ms, size_t rounds) {
  return per_round_ms * static_cast<double>(rounds);
}

}  // namespace common::utils

