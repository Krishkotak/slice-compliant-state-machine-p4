/* ============================================================
   Slice Compliance State Machine (SCSM) — Data Plane (P4_16)
   Spec: VSlice/SCSM PoC — Unified Transition Architecture
   Target: bmv2 simple_switch (v1model)
   ============================================================ */

#include <core.p4>
#include <v1model.p4>

// ─────────────────────────────────────────
// Constants
// ─────────────────────────────────────────
const bit<16> ETHERTYPE_SCSM  = 0x88B5;
const bit<8>  UNDEFINED_NODE  = 0xFF;    // ⊥ — no previous node
const bit<8>  EGRESS_NODE_ID  = 6;       // S6

// ─────────────────────────────────────────
// Headers
// ─────────────────────────────────────────
header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header scsm_h {
    bit<8>  slice_id;
    bit<8>  chain_id;
    bit<8>  chain_idx;
    bit<8>  prev_node;
    bit<32> tau;
    bit<16> inner_ether_type;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> id;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

struct headers_t {
    ethernet_h  ethernet;
    scsm_h      scsm;
    ipv4_h      ipv4;
}

struct metadata_t {
    bit<8>  this_node;        // node ID of this switch
    bit<8>  new_chain_idx;    // updated chain progress
    bit<32> new_tau;          // updated authenticator
    bit<1>  violation;        // 1 = compliance violation
}

// ─────────────────────────────────────────
// Parser
// ─────────────────────────────────────────
parser SCSMParser(packet_in pkt,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t std_meta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_SCSM : parse_scsm;
            default        : accept;
        }
    }
    state parse_scsm {
        pkt.extract(hdr.scsm);
        transition select(hdr.scsm.inner_ether_type) {
            0x0800  : parse_ipv4;
            default : accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control SCSMVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ─────────────────────────────────────────
// Ingress Control
// ─────────────────────────────────────────
control SCSMIngress(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t std_meta) {

    // ── Table 1: node_config ─────────────────────────────────────────
    action set_node_id(bit<8> node_id) {
        meta.this_node = node_id;
    }
    action node_config_miss() {
        meta.violation = 1;
    }
    table node_config {
        key = { std_meta.ingress_port : exact; }
        actions        = { set_node_id; node_config_miss; }
        default_action = node_config_miss();
        size = 64;
    }

    // ── Table 2: ingress_init ────────────────────────────────────────
    action init_tag(bit<8> slice_id, bit<8> chain_id,
                    bit<32> tau0, bit<16> inner_etype) {
        hdr.scsm.setValid();
        hdr.scsm.slice_id         = slice_id;
        hdr.scsm.chain_id         = chain_id;
        hdr.scsm.chain_idx        = 0;
        hdr.scsm.prev_node        = UNDEFINED_NODE;
        hdr.scsm.tau              = tau0;
        hdr.scsm.inner_ether_type = inner_etype;
        hdr.ethernet.ether_type   = ETHERTYPE_SCSM;
    }
    table ingress_init {
        key = {
            std_meta.ingress_port   : exact;
            hdr.ethernet.ether_type : ternary;
        }
        actions        = { init_tag; NoAction; }
        default_action = NoAction();
        size = 128;
    }

    // ── Table 3: t_scsm_transition (Unified Verification) ────────────
    // Replaces predecessor_check, chain_step, and tau_update
    action action_execute_transition(bit<8> new_chain_idx, bit<32> key_material) {
        meta.new_chain_idx = new_chain_idx;
        meta.new_tau = hdr.scsm.tau
                       ^ key_material
                       ^ ((bit<32>)meta.this_node << 8)
                       ^ (bit<32>)meta.new_chain_idx;
    }

    action action_raise_violation() {
        // Triggers the absorbing violation state.
        meta.violation = 1;
        // Freeze the state. By not updating tau, S6 verification is mathematically guaranteed to fail.
        meta.new_chain_idx = hdr.scsm.chain_idx;
        meta.new_tau = hdr.scsm.tau;
    }

    table t_scsm_transition {
        key = {
            hdr.scsm.slice_id       : exact;
            hdr.scsm.chain_id       : exact;
            hdr.scsm.chain_idx      : exact;
            hdr.scsm.prev_node      : exact;
            std_meta.ingress_port   : exact;
        }
        actions = {
            action_execute_transition;
            action_raise_violation;
        }
        default_action = action_raise_violation();
        size = 1024;
    }

    // ── Table 4: egress_verify ───────────────────────────────────────
    action egress_compliant() { }
    action egress_non_compliant() {
        meta.violation = 1;
    }
    table egress_verify {
        key = {
            hdr.scsm.slice_id  : exact;
            meta.this_node     : exact;
            hdr.scsm.chain_idx : exact;   // post-update value
            meta.violation     : exact;   // must be 0
            meta.new_tau       : exact;
        }
        actions        = { egress_compliant; egress_non_compliant; }
        default_action = egress_non_compliant();
        size = 256;
    }

    // ── Table 5: forwarding ──────────────────────────────────────────
    action forward(bit<9> port) {
        std_meta.egress_spec = port;
    }
    action drop_pkt() {
        mark_to_drop(std_meta);
    }
    
    table forwarding {
        key = {
            hdr.ethernet.dst_addr : exact;
            hdr.scsm.slice_id     : ternary;
            std_meta.ingress_port : ternary;
        }
        actions        = { forward; drop_pkt; }
        default_action = drop_pkt();
        size = 1024;
    }
    
    // ── Table 6: is_egress_node ──────────────────────────────────────
    table is_egress_node {
        key = {
            hdr.scsm.slice_id : exact;
            meta.this_node    : exact;
        }
        actions        = { egress_compliant; NoAction; }
        default_action = NoAction();
        size = 64;
    }

    // ── Pipeline apply ───────────────────────────────────────────────
    apply {
        meta.violation     = 0;
        meta.new_chain_idx = 0;
        meta.new_tau       = 0;

        // Step 1: resolve local node ID
        node_config.apply();

        // Step 2: stamp tag on fresh packets at ingress node
        if (!hdr.scsm.isValid()) {
            ingress_init.apply();
        }

        // If it is still not valid, it's background traffic — forward and exit
        if (!hdr.scsm.isValid()) {
            forwarding.apply();
            return;
        }

        // Step 3: Unified State Transition, Topology, & Integrity Check
        t_scsm_transition.apply();

        // Write updated state into header.
        // If a violation occurred, new_chain_idx and new_tau remain frozen.
        hdr.scsm.chain_idx = meta.new_chain_idx;
        hdr.scsm.prev_node = meta.this_node;
        hdr.scsm.tau       = meta.new_tau;

        // Step 4: egress verification at S6
        if (is_egress_node.apply().hit) {
            egress_verify.apply();
            
            // Strip SCSM tag before delivering to H2 (compliant path only)
            if (meta.violation == 0) {
                hdr.ethernet.ether_type = hdr.scsm.inner_ether_type;
                hdr.scsm.setInvalid();
            }
        }

        // Step 5: forward (compliant and violation packets alike)
        forwarding.apply();
    }
}

control SCSMEgress(inout headers_t hdr,
                   inout metadata_t meta,
                   inout standard_metadata_t std_meta) {
    apply { }
}

control SCSMComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.total_len, hdr.ipv4.id, hdr.ipv4.flags,
              hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.src_addr, hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}

control SCSMDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.scsm);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(
    SCSMParser(),
    SCSMVerifyChecksum(),
    SCSMIngress(),
    SCSMEgress(),
    SCSMComputeChecksum(),
    SCSMDeparser()
) main;