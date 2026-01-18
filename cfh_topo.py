#!/usr/bin/env python3
"""
Mininet + BMv2 Assist Protocol Template
- D-Hosts: h1
- RDMA Host: h2
- Helper hosts: h3, h4, h5 (multicast listeners)
- Root-namespace dummy switch: s1
- BMv2 attaches to s1-eth1 and s1-eth2
- Test ping and UDP distress packets
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
THRIFT_PORT = 9090
class DummySwitch(Node):
    """Root-namespace switch placeholder for BMv2."""
    def config(self, **params):
        super(DummySwitch, self).config(inNamespace=False, **params)

def send_distress_packet(src, dst_ip):
    """
    Send a UDP packet to dst_ip:4792 from the host src inside its namespace
    """
    print(f"Sending distress packet from {src.name} -> {dst_ip}")
    cmd = f""""""
    src.cmd(cmd)

def continuous_distress(src, dst_ip, interval=5):
    """
    Continuously send distress packets every `interval` seconds.
    """
    def loop():
        while True:
            send_distress_packet(src, dst_ip)
            time.sleep(interval)
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

class AssistCLI(CLI):

    def do_senddistress(self, line):
        args = line.split()
        if len(args) != 2:
            print("Usage: senddistress <src> <dst_ip>")
            return
        src_name, dst_ip = args
        if src_name not in self.mn:
            print(f"Host {src_name} not found")
            return
        send_distress_packet(self.mn[src_name], dst_ip)

def bmv2_runtime_cli(node, cmd):
    """Send a single command to BMv2 CLI and give it a moment to commit."""
    node.cmd(f"simple_switch_CLI --thrift-port {THRIFT_PORT} <<EOF\n{cmd}\nEOF")
    time.sleep(0.05)


def run():
    net = Mininet(controller=None, link=TCLink)

    # -------------------
    # Create hosts
    # -------------------
    h1 = net.addHost('h1', ip='10.0.0.5/24')        # D-Host
    RDMAHost = net.addHost('h2', ip='10.0.0.6/24') # Normal RDMA host

    # Helper hosts (multicast listeners)
    helpers = []
    for i in range(3, 6):  # h3, h4, h5
        h = net.addHost(f'h{i}', ip=f'10.0.0.{i+2}/24')
        helpers.append(h)

    # Root-namespace dummy switch
    s1 = net.addHost('s1', cls=DummySwitch)

    # -------------------
    # Create links
    # -------------------
    net.addLink(h1, s1)
    net.addLink(RDMAHost, s1)
    for h in helpers:
        net.addLink(h, s1)

    # -------------------
    # Start network
    # -------------------
    net.start()

    # Bring up switch interfaces in root namespace
    for intf in s1.intfList():
        intf.config(up=True)
    print("\nSwitch interfaces (root namespace) for BMv2:")
    for intf in s1.intfList():
        print(intf)

    # Bring up host interfaces inside namespaces
    for h in [h1, RDMAHost] + helpers:
        for intf in h.intfList():
            intf.config(up=True)
            # Add IP in case missing
            if not h.cmd(f'ip addr show {intf} | grep "inet "'):
                h.cmd(f'ip addr add {h.IP()}/24 dev {intf}')
            intf.config(up=True)

    # -------------------
    # Start tcpdump
    # -------------------
    start_tcpdump(h1, f"{LOG_DIR}/h1_tcpdump.log")
    start_tcpdump(RDMAHost, f"{LOG_DIR}/RDMAHost_tcpdump.log")
    for h in helpers:
        start_tcpdump(h, f"{LOG_DIR}/{h.name}_tcpdump.log", protocol="ip") # these guys are not listening on UDP for this packet
    start_switch_tcpdump(s1, f"{LOG_DIR}/s1_tcpdump.log")
    # -------------------
    # Launch BMv2 switch
    # -------------------
    intfs = s1.intfList()
    cmd = (
        f"simple_switch --log-console "
        f"--thrift-port {THRIFT_PORT} "
        f"-i 1@{intfs[0]} -i 2@{intfs[1]} "
    )
    # Add extra interfaces for helper hosts
    for idx, h in enumerate(helpers, start=3):
        cmd += f"-i {idx}@{intfs[idx-1]} "
    cmd += f"/work/assist/CFH_TOR.json > {LOG_DIR}/bmv2.log 2>&1 &"
    print(f"\nLaunching BMv2: {cmd}")
    s1.cmd(cmd)
    time.sleep(1)  # Give BMv2 a moment to start

    # -------------------
    # Configure multicast group dynamically
    # -------------------
    # Runtime configuration: multicast + mirroring
    # -------------------
    def configure_bmv2_multicast_and_mirroring(switch, mcast_grp=1, node_id=10, node_ports=[3,4,5], mirror_session=1):
        import time

        def bmv2_cli(cmd):
            out = switch.cmd(f'echo "{cmd}" | simple_switch_CLI --thrift-port {THRIFT_PORT}')
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

    # Apply runtime configuration
    configure_bmv2_multicast_and_mirroring(s1, mcast_grp=1, node_id=1, node_ports=[3,4,5], mirror_session=1)

    # -------------------
    # Optional: continuous distress packet for testing
    # -------------------
    #continuous_distress(h1, RDMAHost.IP(), interval=5)

    # -------------------
    # Launch custom CLI
    # -------------------
    AssistCLI(net)

    # -------------------
    # Stop tcpdump and network
    # -------------------
    for node in [h1, RDMAHost, s1] + helpers:
        node.cmd("kill %tcpdump")
    net.stop()


def start_switch_tcpdump(switch, outfile):
    for intf in switch.intfList():
        switch.cmd(f"tcpdump -i {intf} -nn -vv ip > {outfile} 2>&1 &")
        print(f"Starting tcpdump on {switch.name}:{switch.defaultIntf()} -> {outfile}")

def start_tcpdump(node, outfile, protocol="udp"):
    """
    Start tcpdump on a node/interface and write to  file
    """
    node.cmd(f"tcpdump -i {node.defaultIntf()} -nn -vv {protocol} > {outfile} 2>&1 &")
    print(f"Starting tcpdump on {node.name}:{node.defaultIntf()} -> {outfile}")

if __name__ == '__main__':
    setLogLevel('info')
    run()
