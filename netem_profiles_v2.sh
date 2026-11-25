#!/usr/bin/env bash
# Apply a named network profile to an interface for the latency / throughput runs in Section 6.14.
set -euo pipefail
IF="${1:?interface}"; PROFILE="${2:?lan|wan|wan_jitter|mobile|clear}"
case "$PROFILE" in
  lan)        tc qdisc replace dev "$IF" root netem delay 0.2ms 0.05ms ;;
  wan)        tc qdisc replace dev "$IF" root netem delay 20ms 2ms loss 0.1% ;;
  wan_jitter) tc qdisc replace dev "$IF" root netem delay 35ms 15ms distribution normal loss 0.5% ;;
  mobile)     tc qdisc replace dev "$IF" root netem delay 60ms 25ms distribution normal loss 1% rate 50mbit ;;
  clear)      tc qdisc del dev "$IF" root 2>/dev/null || true ;;
esac
tc qdisc show dev "$IF"
