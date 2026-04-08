# Asterisk2.0 vs Asterisk (100 sequential multiplications)

Environment:
- parties: `n=3` computing + `1` helper
- circuit: `g=1`, `d=100` (100 chain multiplications)
- repeat: `1`
- security model: `semi-honest`

## Commands
```sh
# Optional network simulation in code path:
#   --sim-latency-ms 2 --sim-bandwidth-mbps 50
# Optional communication-cost model preset:
#   --net-preset lan   (or wan)
for pid in 0 1 2 3; do
  ./benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 \
    --security-model semi-honest --sim-latency-ms 0 --sim-bandwidth-mbps 0 --parallel-send \
    -o /tmp/asterisk2_chain100_p"$pid".json &
done
wait

for pid in 0 1 2 3; do
  ./benchmarks/asterisk_offline --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 -o /tmp/asterisk_offline_chain100_p"$pid".json &
done
wait

for pid in 0 1 2 3; do
  ./benchmarks/asterisk_online --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 -o /tmp/asterisk_online_chain100_p"$pid".json &
done
wait
```

## Results (ms / bytes / comm-count)
- Asterisk2.0 computing parties average (after batched-open optimization)
  - offline: `0.423747 ms`
  - online: `7.051593 ms`
  - offline bytes: `0`
  - online bytes: `400`
  - offline comm-count: `0`
  - online comm-rounds: `100`
  - online send-count: `100` (with `--parallel-send`)
- Asterisk2.0 helper party
  - offline: `0.745918 ms`
  - offline bytes: `300`
  - offline comm-count: `100`
- Asterisk baseline computing parties average
  - offline: `1.287365 ms`
  - online: `5.918904 ms`
  - offline bytes: `826.67`
  - online bytes: `533.33`

## Quick takeaways
- Compared with the previous unbatched implementation (`online ~= 14.94 ms`),
  batched-open reduces Asterisk2.0 online time by about 2.1x in this setup.
- For this setup, Asterisk2.0 has lower offline latency for computing parties,
  while online is now much closer to Asterisk baseline (`7.05 ms` vs `5.92 ms`).
- Multiplication-round view:
  - Asterisk2.0: one batched-open interactive round per multiplicative depth (`100` rounds here).
  - Asterisk (current implementation path): two aggregation exchanges per depth for multiplication values,
    i.e. about `2 * depth = 200` interaction rounds in this test shape.

## Simulated network run (latency=2ms, bandwidth=50Mbps)

Command parameters:
- Asterisk2.0: `--sim-latency-ms 2 --sim-bandwidth-mbps 50`
- Asterisk online baseline: `--sim-latency-ms 2 --sim-bandwidth-mbps 50 --sim-rounds-per-depth 2`

Observed averages (n=3 computing parties, g=1, d=100):
- Asterisk2.0 online raw time: `448.591495 ms`
- Asterisk2.0 online bytes: `400`
- Asterisk online raw time: `6.678695 ms`
- Asterisk online simulated time: `406.764029 ms`
- Asterisk online bytes: `533.33`
- With `--parallel-send`, Asterisk2.0 uses parallel peer send/recv during batched-open, and
  `online_send_count` is reported with parallel-link accounting (one logical send per round).
  For narrow levels (e.g., `g=1`), runtime automatically falls back to serial I/O to avoid
  thread-management overhead.
- If communication-cost model options are enabled (`--net-preset` or custom
  `--bandwidth-bps/--latency-ms`), benchmark output also includes:
  `comm_model_round_ms` and `comm_model_total_ms`.
