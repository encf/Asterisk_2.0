#!/usr/bin/env python3
"""Simple communication-cost model for MPC experiments.

Model (simplified):
  round_time = latency_ms + (bytes_sent * 8) * 1000 / bandwidth_bps

All-to-all variant (shared outgoing bandwidth):
  round_time = latency_ms + (msg_size_bytes * (n - 1) * 8) * 1000 / bandwidth_bps

This model includes propagation + transmission delay, and ignores queueing,
packetization and protocol overhead.
"""

from __future__ import annotations

import argparse


PRESETS = {
    "lan": {"bandwidth_bps": 1_000_000_000, "latency_ms": 1.0},
    "wan": {"bandwidth_bps": 100_000_000, "latency_ms": 20.0},
}


def estimate_round_ms(bytes_sent: int, bandwidth_bps: int, latency_ms: float) -> float:
    tx_ms = (bytes_sent * 8.0) * 1000.0 / bandwidth_bps
    return latency_ms + tx_ms


def estimate_all_to_all_round_ms(
    msg_size_bytes: int, parties: int, bandwidth_bps: int, latency_ms: float
) -> float:
    total_outgoing = msg_size_bytes * max(parties - 1, 0)
    return estimate_round_ms(total_outgoing, bandwidth_bps, latency_ms)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preset", choices=["lan", "wan"], default=None)
    parser.add_argument("--bandwidth-bps", type=int, default=0)
    parser.add_argument("--latency-ms", type=float, default=0.0)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--bytes-sent", type=int, default=0)
    parser.add_argument("--msg-size-bytes", type=int, default=0)
    parser.add_argument("--parties", type=int, default=0)
    args = parser.parse_args()

    bandwidth_bps = args.bandwidth_bps
    latency_ms = args.latency_ms
    if args.preset:
        bandwidth_bps = PRESETS[args.preset]["bandwidth_bps"]
        latency_ms = PRESETS[args.preset]["latency_ms"]
    if args.bandwidth_bps > 0:
        bandwidth_bps = args.bandwidth_bps
    if args.latency_ms > 0:
        latency_ms = args.latency_ms

    if bandwidth_bps <= 0:
        raise SystemExit("bandwidth_bps must be > 0 (or provide --preset)")

    if args.msg_size_bytes > 0 and args.parties > 0:
        round_ms = estimate_all_to_all_round_ms(
            args.msg_size_bytes, args.parties, bandwidth_bps, latency_ms
        )
        mode = "all_to_all"
    else:
        round_ms = estimate_round_ms(args.bytes_sent, bandwidth_bps, latency_ms)
        mode = "generic"

    total_ms = round_ms * max(args.rounds, 0)
    print(f"mode={mode}")
    print(f"bandwidth_bps={bandwidth_bps}")
    print(f"latency_ms={latency_ms}")
    print(f"round_time_ms={round_ms:.6f}")
    print(f"total_time_ms={total_ms:.6f}")


if __name__ == "__main__":
    main()

