#!/usr/bin/env python3
"""A3E-DNS v2 testbed topology (Section 6.11.1): clients - switch - resolver, with netem profiles.
Only benign traffic generation and link emulation live here. Attack scenarios are replayed at feature
level by src/a3e_dns_v2/traffic.py; any live attack tooling must be run on an isolated, authorised lab.
Run: sudo python3 mininet_topology_v2.py --profile wan_jitter
"""
import argparse
PROFILES = {
 "lan":        dict(delay="0.2ms", jitter="0.05ms", loss=0.0, bw=10000),
 "wan":        dict(delay="20ms",  jitter="2ms",    loss=0.1, bw=1000),
 "wan_jitter": dict(delay="35ms",  jitter="15ms",   loss=0.5, bw=500),
 "mobile":     dict(delay="60ms",  jitter="25ms",   loss=1.0, bw=50),
}
def build(profile, n_clients):
    from mininet.net import Mininet
    from mininet.node import OVSSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    setLogLevel("info"); p = PROFILES[profile]
    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)
    s1 = net.addSwitch("s1", failMode="standalone"); res = net.addHost("resolver", ip="10.0.2.2/24")
    net.addLink(res, s1, bw=p["bw"])
    for i in range(n_clients):
        c = net.addHost(f"c{i+1}", ip=f"10.0.1.{i+1}/24")
        net.addLink(c, s1, bw=p["bw"], delay=p["delay"], jitter=p["jitter"], loss=p["loss"])
    return net
if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--profile", default="wan", choices=PROFILES); ap.add_argument("--clients", type=int, default=8); a = ap.parse_args()
    net = build(a.profile, a.clients); net.start()
    from mininet.cli import CLI; CLI(net); net.stop()
