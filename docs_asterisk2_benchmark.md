# Asterisk2.0 vs Asterisk (100 sequential multiplications)

Environment:
- parties: `n=3` computing + `1` helper
- circuit: `g=1`, `d=100` (100 chain multiplications)
- repeat: `1`
- security model: `semi-honest`

## Commands
```sh
for pid in 0 1 2 3; do
  ./benchmarks/asterisk2_mpc --localhost -n 3 -p "$pid" -g 1 -d 100 -r 1 --security-model semi-honest -o /tmp/asterisk2_chain100_p"$pid".json &
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
- Asterisk2.0 computing parties average
  - offline: `0.495635 ms`
  - online: `14.938681 ms`
  - offline bytes: `0`
  - online bytes: `400`
  - offline comm-count: `0`
  - online comm-count: `400`
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
- For this setup, Asterisk2.0 has lower offline latency for computing parties, but higher online latency.
- Asterisk2.0 online communication count/bytes are higher in this implementation due to opening `d,e` per multiplication via all-to-all exchange.
