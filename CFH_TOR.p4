// cfh_tor.p4
#include <core.p4>
#include <v1model.p4>


// CFH Control Message Types
const bit<8> CFH_ADVERTISE = 1;
const bit<8> CFH_OFFER     = 2;
const bit<8> CFH_WITHDRAW  = 3;
const bit<8> IP_PROTO_CFH = 253;
const bit<16> CFH_UDP_PORT = 5005;
const bit<16> RDMA_UDP_PORT = 4791;

// -------------------------
// Metadata
// -------------------------
struct metadata_t {
    bit<1> trigger_ctrl;
    bit<32> ctrl_idx;
}
// -------------------------
// Header definitions
// -------------------------
// CFH-Control header (16 bytes)
header cfh_ctrl_t {
    bit<8>  version;              // CFH version
    bit<8>  msg_type;             // ADVERTISE / OFFER / WITHDRAW
    bit<8>  ttl;                  // distress lifetime (seconds or hops)
    bit<8>  flags;

    bit<32> distressed_host_id;   // logical ID of D-Host
    bit<32> tor_id;               // TOR originating this message, (may not need this)
    bit<32> request_id;           // will correlates with cached CFH entry
}

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

// CFH Header (31 bytes)
header cfh_t {
    bit<8> version;
    bit<32> length_;
    bit<32> request_id;
    bit<8> ttl;
    bit<8> signal;
    bit<32> d_host_id;
    bit<32> rdma_host_id;
    bit<32> rkey;
    bit<64> mr_base_addr;
}



// -------------------------
// Header union / struct
// -------------------------
struct headers_t {
    ethernet_t eth;
    ipv4_t    ipv4;
    udp_t     udp;
    cfh_t     cfh;
    cfh_ctrl_t  cfh_ctrl;
}


control MyVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply { }
}


/* =======================
 * Compute checksum (required by v1model)
 * ======================= */
control MyComputeChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply { }
}

// -------------------------
// Parser
// -------------------------
parser MyParser(packet_in pkt,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta) {

    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            IP_PROTO_CFH: parse_cfh_ctrl;  // control plane
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

// -------------------------
// Registers (CFH cache)
// -------------------------
register<bit<32>>(1024) cfh_dhost_id;
register<bit<32>>(1024) cfh_rdma_host_id;
register<bit<32>>(1024) cfh_rkey;
register<bit<64>>(1024) cfh_mr_base_addr;
register<bit<32>>(1024) cfh_length;
register<bit<32>>(1024) cfh_request_id;
register<bit<32>>(1024) reg_dhost_id;
register<bit<32>>(1024) reg_request_id;

// -------------------------
// Ingress
// -------------------------
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_meta) {

    apply {
        if (hdr.eth.etherType == 0x0806) {
            if (standard_meta.ingress_port == 1) {
                standard_meta.egress_spec = 2;
            } else if (standard_meta.ingress_port == 2) {
                standard_meta.egress_spec = 1;
            }
        }
        if (hdr.cfh.isValid()) {
            bit<32> idx;
            idx = hdr.cfh.request_id % 1024;

            // Cache for control packet
            reg_dhost_id.write(idx, hdr.cfh.d_host_id);
            reg_request_id.write(idx, hdr.cfh.request_id);


            cfh_dhost_id.write(idx, hdr.cfh.d_host_id); 
            cfh_rdma_host_id.write(idx, hdr.cfh.rdma_host_id);
            cfh_rkey.write(idx, hdr.cfh.rkey);
            cfh_mr_base_addr.write(idx, hdr.cfh.mr_base_addr); 
            cfh_length.write(idx, hdr.cfh.length_); 
            cfh_request_id.write(idx, hdr.cfh.request_id);            // Mark that we need a control clone
            meta.trigger_ctrl = 1;
            meta.ctrl_idx = idx;
            clone_preserving_field_list(CloneType.I2E, 1, 0);
            // Strip CFH for RDMA host
            hdr.cfh.setInvalid();
            hdr.udp.dstPort = RDMA_UDP_PORT;
        }
        if (standard_meta.ingress_port == 1) {
            standard_meta.egress_spec = 2;
        } else if (standard_meta.ingress_port == 2) {
            standard_meta.egress_spec = 1;
        }
    }
}

// -------------------------
// Egress 
// -------------------------
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_meta) {

    apply {
        if (standard_meta.instance_type == 1) {
            // Multicast across DC
            standard_meta.mcast_grp = 1;
            standard_meta.egress_spec = 0;
            log_msg("Egress clone: building CFH_ADVERTISE");
            bit<32> dhost;
            bit<32> req;

            reg_dhost_id.read(dhost, meta.ctrl_idx);
            reg_request_id.read(req, meta.ctrl_idx);

            // Strip everything not needed
            hdr.udp.setInvalid();
            hdr.cfh.setInvalid();

            // Build CFH-Control
            hdr.cfh_ctrl.setValid();
            hdr.ipv4.setValid();
            hdr.eth.setValid();

            hdr.ipv4.version = 4;
            hdr.ipv4.ihl = 5;
            hdr.ipv4.protocol = IP_PROTO_CFH;
            hdr.ipv4.ttl = 64;

            hdr.cfh_ctrl.version = 1;
            hdr.cfh_ctrl.msg_type = CFH_ADVERTISE;
            hdr.cfh_ctrl.ttl = 10;
            hdr.cfh_ctrl.flags = 0;
            hdr.cfh_ctrl.distressed_host_id = dhost;
            hdr.cfh_ctrl.request_id = req;
        }
    }
}

// -------------------------
// Deparser
// -------------------------
control MyDeparser(packet_out pkt,
                   in headers_t hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.cfh);
        pkt.emit(hdr.cfh_ctrl);
    }
}

// -------------------------
// Pipeline
// -------------------------
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
