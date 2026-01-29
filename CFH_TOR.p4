// cfh_tor.p4
#include <core.p4>
#include <v1model.p4>

/* =======================
 * Constants
 * ======================= */
const bit<16>  ARP_MCAST_GRP  = 100;
const bit<8>  CFH_ADVERTISE = 1;
const bit<8>  CFH_AVAIL     = 2;
const bit<8>  CFH_COMMIT  = 3;

const bit<8>  IP_PROTO_CFH  = 253;
const bit<16> CFH_UDP_PORT  = 5005;
const bit<16> RDMA_UDP_PORT = 4791;

/* =======================
 * Metadata
 * ======================= */
struct metadata_t {
    bit<1>  trigger_ctrl;
    bit<32> ctrl_idx;
};

/* =======================
 * Headers
 * ======================= */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// CFH data-plane header
header cfh_t {
    bit<8>  version;
    bit<32> length_;
    bit<32> request_id;
    bit<8>  ttl;
    bit<8>  signal;
    bit<32> d_host_id;
    bit<32> rdma_host_id;
    bit<32> rkey;
    bit<64> mr_base_addr;
}

// CFH control-plane header
header cfh_ctrl_t {
    bit<8>  version;
    bit<8>  msg_type;
    bit<8>  ttl;
    bit<8>  flags;
    bit<32> distressed_host_id;
    bit<32> tor_id;
    bit<32> request_id;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}
/* =======================
 * Header Struct
 * ======================= */
struct headers_t {
    ethernet_t eth;
    ipv4_t     ipv4;
    udp_t      udp;
    cfh_t      cfh;
    cfh_ctrl_t cfh_ctrl;
    arp_t      arp;
};

/* =======================
 * Parser
 * ======================= */
parser MyParser(packet_in pkt,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t sm) {

    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            IP_PROTO_CFH: parse_cfh_ctrl;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            CFH_UDP_PORT: parse_cfh;
            default: accept;
        }
    }

    state parse_cfh {
        pkt.extract(hdr.cfh);
        transition accept;
    }

    state parse_cfh_ctrl {
        pkt.extract(hdr.cfh_ctrl);
        transition accept;
    }
}

/* =======================
 * Registers (CFH cache)
 * ======================= */
register<bit<32>>(1024) reg_dhost_id;
register<bit<32>>(1024) reg_request_id;
register<bit<32>>(1024) reg_rdma_host_id;
register<bit<32>>(1024) reg_rkey;
register<bit<64>>(1024) reg_mr_base;
register<bit<32>>(1024) reg_length;

/* =======================
 * Ingress
 * ======================= */
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t sm) {


    action drop() {
        mark_to_drop(sm);
    }

    action set_egress(bit<9> port, bit<48> dst_mac) {
        sm.egress_spec = port;
        hdr.eth.dstAddr = dst_mac;
        log_msg("Forwarding to port %0d %0d", port, dst_mac);
    }

    action set_l2_egress_port(bit<9> port) {
        sm.egress_spec = port;
    }
    action flood() {
        sm.mcast_grp = ARP_MCAST_GRP;
        sm.egress_spec = 0;
    }

    table l2_forward {
        key = {
            hdr.eth.dstAddr : exact;
        }
        actions = {
            set_l2_egress_port;
            flood;
            drop;
        }
    }


    // Tables must be defined inside the control block
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_egress;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        meta.trigger_ctrl = 0;

        /* ---- CFH interception ---- */
        if (hdr.cfh.isValid()) {
            bit<32> idx = hdr.cfh.request_id % 1024;

            reg_dhost_id.write(idx, hdr.cfh.d_host_id);
            reg_request_id.write(idx, hdr.cfh.request_id);
            reg_rdma_host_id.write(idx, hdr.cfh.rdma_host_id);
            reg_rkey.write(idx, hdr.cfh.rkey);
            reg_mr_base.write(idx, hdr.cfh.mr_base_addr);
            reg_length.write(idx, hdr.cfh.length_);

            meta.trigger_ctrl = 1;
            meta.ctrl_idx = idx;

            clone_preserving_field_list(CloneType.I2E, 1, 0);

            /* Forward RDMA normally */
            hdr.cfh.setInvalid();
            hdr.udp.dstPort = RDMA_UDP_PORT;
        }
        if (hdr.arp.isValid()) {
            log_msg("ARP packet flooded");
            flood();

        }
        /* ---- L2 forwarding ---- */
        if (hdr.eth.isValid()) {
            l2_forward.apply();
        }

        /* ---- Inter Rack forwarding ---- */
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/* =======================
 * Egress
 * ======================= */
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t sm) {

    apply {
        if (sm.instance_type == 1) {
            /* Multicast across fabric */
            sm.mcast_grp = 1;
            sm.egress_spec = 0;
            log_msg("Egress clone: building CFH_ADVERTISE");
            bit<32> dhost;
            bit<32> req;

            reg_dhost_id.read(dhost, meta.ctrl_idx);
            reg_request_id.read(req, meta.ctrl_idx);

            /* Strip data-plane headers */
            hdr.udp.setInvalid();
            hdr.cfh.setInvalid();

            /* Build CFH_ADVERTISE */
            hdr.cfh_ctrl.setValid();
            hdr.ipv4.setValid();
            hdr.eth.setValid();

            hdr.ipv4.version  = 4;
            hdr.ipv4.ihl      = 5;
            hdr.ipv4.protocol = IP_PROTO_CFH;
            hdr.ipv4.ttl      = 64;

            hdr.cfh_ctrl.version = 1;
            hdr.cfh_ctrl.msg_type = CFH_ADVERTISE;
            hdr.cfh_ctrl.ttl = 10;
            hdr.cfh_ctrl.flags = 0;
            hdr.cfh_ctrl.distressed_host_id = dhost;
            hdr.cfh_ctrl.request_id = req;

        }
    }
}

/* =======================
 * Checksums (noop)
 * ======================= */
control MyVerifyChecksum(inout headers_t hdr,
                         inout metadata_t meta) { apply { } }

control MyComputeChecksum(inout headers_t hdr,
                          inout metadata_t meta) { apply { } }

/* =======================
 * Deparser
 * ======================= */
control MyDeparser(packet_out pkt,
                   in headers_t hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.cfh);
        pkt.emit(hdr.cfh_ctrl);
    }
}

/* =======================
 * Switch
 * ======================= */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
