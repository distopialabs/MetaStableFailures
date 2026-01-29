#!/usr/bin/env python3
"""
Mininet + BMv2 Assist Protocol Template (CLOS)
- 3 Racks
- 4 hosts per rack
- 3 TORs
- 2 Spines
- DummySwitch + BMv2 launch model
"""

from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import threading
import time
import os

LOG_DIR = "./logs"
THRIFT_BASE = 9090
P4_JSON = "/work/assist/CFH_TOR.json"
NUM_HOSTS_PER_RACK = 4

os.makedirs(LOG_DIR, exist_ok=True)

def install_l2_rules(tor, rules):
    """
    rules: list of (dst_mac, port)
    """
    for mac, port in rules:
        cmd = f"table_add l2_forward set_l2_egress_port {mac} => {port}"
        print(f"[BMv2] {cmd}")
        tor.cmd(f"simple_switch_CLI --thrift-port {THRIFT_BASE} <<EOF\n{cmd}\nEOF")
        # thrift port might need to change later, lets see
        time.sleep(0.05)


# -------------------------------------------------------------------
# DummySwitch
# -------------------------------------------------------------------
class DummySwitch(Node):
    def config(self, **params):
        super(DummySwitch, self).config(inNamespace=False, **params)

# -------------------------------------------------------------------
# tcpdump helpers
# -------------------------------------------------------------------
def start_switch_tcpdump(switch, outfile):
    for intf in switch.intfList():
        switch.cmd(f"tcpdump -i {intf} -nn -vv ip > {outfile} 2>&1 &")

def start_tcpdump(node, outfile, protocol="ip"):
    node.cmd(f"tcpdump -i {node.defaultIntf()} -nn -vv > {outfile} 2>&1 &")

# -------------------------------------------------------------------
# BMv2 launcher
# -------------------------------------------------------------------
def launch_bmv2(switch, thrift_port, logfile):
    intfs = switch.intfList()
    cmd = f"simple_switch --log-console --thrift-port {thrift_port} "
    for idx, intf in enumerate(intfs, start=1):
        cmd += f"-i {idx}@{intf} "
    cmd += f"{P4_JSON} > {logfile} 2>&1 &"
    print(f"[BMv2] {switch.name}: {cmd}")
    switch.cmd("rm -f /tmp/bmv2-*")  # same cleanup requirement
    switch.cmd(cmd)
    time.sleep(1)

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
def run():
    net = Mininet(controller=None, link=TCLink)

    # -------------------
    # Create hosts
    # -------------------
    hosts = []
    for i in range(1, 13):
        h = net.addHost(f"h{i}", 
                        ip=f"10.0.{(i-1)//4}.{i}/24", 
                        mac = "00:00:00:00:{:02x}:{:02x}".format((i-1)//4 + 1, i))
        hosts.append(h)

    # -------------------
    # Create switches
    # -------------------
    tor1 = net.addHost("tor1", cls=DummySwitch)
    tor2 = net.addHost("tor2", cls=DummySwitch)
    tor3 = net.addHost("tor3", cls=DummySwitch)

    spine1 = net.addHost("spine1", cls=DummySwitch)
    spine2 = net.addHost("spine2", cls=DummySwitch)

    # -------------------
    # Rack wiring
    # -------------------
    for h in hosts[0:4]:
        net.addLink(h, tor1)
    for h in hosts[4:8]:
        net.addLink(h, tor2)
    for h in hosts[8:12]:
        net.addLink(h, tor3)

    # -------------------
    # CLOS fabric
    # -------------------
    for tor in [tor1, tor2, tor3]:
        net.addLink(tor, spine1)
        net.addLink(tor, spine2)

    net.addLink(spine1, spine2)

    # -------------------
    # Start network
    # -------------------
    net.start()

    # Bring up interfaces
    for n in hosts + [tor1, tor2, tor3, spine1, spine2]:
        for intf in n.intfList():
            intf.config(up=True)
    tor_hosts = { "tor1": hosts[0:4], "tor2": hosts[4:8], "tor3": hosts[8:12], } 
    spine_tors = { "spine1": [tor1, tor2, tor3], "spine2": [tor1, tor2, tor3], }
    # -------------------
    # Logging
    # -------------------
    for h in hosts:
        start_tcpdump(h, f"{LOG_DIR}/{h.name}.log")

    for sw in [tor1, tor2, tor3, spine1, spine2]:
        start_switch_tcpdump(sw, f"{LOG_DIR}/{sw.name}.log")

    # -------------------
    # Launch BMv2 (same pattern, per-switch)
    # -------------------
    switches = [tor1, tor2, tor3, spine1, spine2]
    for i, sw in enumerate(switches):
        launch_bmv2(
            sw,
            THRIFT_BASE + i,
            f"{LOG_DIR}/{sw.name}.log"
        )
    # Build host_info with correct TOR port mapping
    host_info = {}
    for h in hosts:
        host_index = int(h.name[1:])
        tor_port = ((host_index - 1) % 4) + 1
        host_info[h.name] = {
            "ip": h.IP(),
            "mac": h.MAC(),
            "port": tor_port
        }

    # TOR → hosts mapping
    tor_hosts = {
        "tor1": hosts[0:4],
        "tor2": hosts[4:8],
        "tor3": hosts[8:12],
    }

    # Build L2 entries for a TOR
    def build_l2_entries_for_tor(tor_name):
        entries = []
        for h in tor_hosts[tor_name]:
            info = host_info[h.name]
            entries.append((info["mac"], info["port"]))
        return entries

    # Build IPv4 routes for a TOR
    def build_ipv4_routes_for_tor(tor_name):
        routes = []
        for h in tor_hosts[tor_name]:
            info = host_info[h.name]
            routes.append((info["ip"], info["port"], info["mac"]))
        return routes
    
    def install_ipv4_routes(sw, routes):
        for ip, port, mac in routes:
            cmd = f'table_add MyIngress.ipv4_lpm set_egress {ip}/32 => {port} {mac}'
            print(sw.cmd(f'echo "{cmd}" | simple_switch_CLI --thrift-port {THRIFT_BASE}'))

    # Install L2 + L3 automatically
    install_l2_rules(tor1, build_l2_entries_for_tor("tor1"))
    install_ipv4_routes(tor1, build_ipv4_routes_for_tor("tor1"))


    def configure_bmv2_multicast_and_mirroring(switch, mcast_grp=1, node_id=10, node_ports=[3,4,5], mirror_session=1):
        import time

        def bmv2_cli(cmd):
            out = switch.cmd(f'echo "{cmd}" | simple_switch_CLI --thrift-port {THRIFT_BASE}')
            time.sleep(0.05)
            return out

        # Step 1: Create multicast group
        print(f"[BMv2] Creating multicast group {mcast_grp}")
        print(bmv2_cli(f"mc_mgrp_create {mcast_grp}"))

        # Step 2: Create node with specified ports
        ports_str = " ".join(map(str, node_ports))
        print(f"[BMv2] Creating node {node_id} with ports {ports_str}")
        print(bmv2_cli(f"mc_node_create {node_id} {ports_str}"))

        # Step 3: Associate node to multicast group
        print(f"[BMv2] Associating node {0} to multicast group {mcast_grp}")
        print(bmv2_cli(f"mc_node_associate {mcast_grp} {0}"))

        # Step 4: Verify multicast group
        print(f"[BMv2] Dumping multicast groups")
        print(bmv2_cli("mc_dump"))

        # Step 5: Add mirroring (for CFH_CTRL clone)
        print(f"[BMv2] Adding mirroring for multicast group {mcast_grp}")
        print(bmv2_cli(f"mirroring_add_mc {mirror_session} {mcast_grp}"))

        # Step 6: Verify mirroring
        print(f"[BMv2] Dumping mirroring config")
        print(bmv2_cli(f"mirroring_get {mirror_session}"))

        print("[BMv2] Multicast + mirroring configuration complete")
    configure_bmv2_multicast_and_mirroring(tor1, mcast_grp=100, node_id=1, node_ports=[1,2,3,4,5], mirror_session=1)
    # -------------------
    # CLI
    # -------------------
    CLI(net)

    # -------------------
    # Cleanup
    # -------------------
    for n in hosts + switches:
        n.cmd("kill %tcpdump")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
