/* ============================================================
   Slice Compliance State Machine (SCSM) — Data Plane (P4_16)
   Spec: VSlice/SCSM PoC — Software Specification Document
   Target: bmv2 simple_switch (v1model)

   Key changes from previous version:
   - Added chain_id (c) field to SCSM header
   - Violation does NOT drop immediately — packet forwarded with
     violation flag set for observation at egress (S6)
   - Two service chains supported (C1: S2→S3→S6, C2: S4→S5→S6)
   - Unauthorized node SX detection via predecessor_check miss
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

/* In-band compliance tag  T = (s, c, i, v, τ)
   s   : slice identifier          8 bits
   c   : service-chain identifier  8 bits
   i   : chain progress index      8 bits
   v   : previously verified node  8 bits
   tau : integrity authenticator  32 bits
   inner_ether_type: original ethertype of payload (e.g. 0x0800)
*/
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
    // ingress_port → this_node ID
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
    // Stamp initial tag T0 = (s, c, 0, ⊥, τ0) on untagged packets at S1
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

    // ── Table 3: predecessor_check ───────────────────────────────────
    // Key: (slice_id, this_node u, prev_node v) → authorized or violation
    // Miss = unauthorized predecessor (includes SX detection)
    action topology_ok() { }
    action topology_violation() {
        meta.violation = 1;
    }
    table predecessor_check {
        key = {
            hdr.scsm.slice_id  : exact;
            meta.this_node     : exact;
            hdr.scsm.prev_node : exact;
        }
        actions        = { topology_ok; topology_violation; }
        default_action = topology_violation();
        size = 1024;
    }

    // ── Table 4: chain_step ──────────────────────────────────────────
    // Key: (chain_id, this_node) — if this node is next in chain, increment
    action increment_chain() {
        meta.new_chain_idx = hdr.scsm.chain_idx + 1;
    }
    action no_chain_advance() {
        meta.new_chain_idx = hdr.scsm.chain_idx;
    }
    table chain_step {
        key = {
            hdr.scsm.chain_id  : exact;
            meta.this_node     : exact;
            hdr.scsm.chain_idx : exact;
        }
        actions        = { increment_chain; no_chain_advance; }
        default_action = no_chain_advance();
        size = 1024;
    }

    // ── Table 5: tau_update ──────────────────────────────────────────
    // τ' = H(τ || u || i')  — XOR proxy keyed per (slice, node)
    action update_tau(bit<32> key_material) {
        meta.new_tau = hdr.scsm.tau
                       ^ key_material
                       ^ ((bit<32>)meta.this_node << 8)
                       ^ (bit<32>)meta.new_chain_idx;
    }
    table tau_update {
        key = {
            hdr.scsm.slice_id : exact;
            meta.this_node    : exact;
        }
        actions        = { update_tau; }
        default_action = update_tau(0xDEADBEEF);
        size = 256;
    }

    // ── Table 6: egress_verify ───────────────────────────────────────
    // At S6: compliant only if chain_idx == k AND violation == 0 AND tau matches
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

    // ── Table 7: forwarding ──────────────────────────────────────────
    // dst MAC + slice_id → output port
    // NOTE: violation packets are FORWARDED (not dropped) per spec §3.3.6
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
        }
        actions        = { forward; drop_pkt; }
        default_action = drop_pkt();
        size = 1024;
    }

    // ── Table 8: is_egress_node ──────────────────────────────────────
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

        if (!hdr.scsm.isValid()) {
            forwarding.apply();
            return;
        }

        // Step 3: predecessor / topology check (SX detected here via miss)
        predecessor_check.apply();
        // NOTE: violation flag set but packet NOT dropped — forwarded per spec

        // Step 4: service-chain progress (only meaningful if no violation)
        chain_step.apply();

        // Step 5: τ update — τ' = H(τ || u || i')
        tau_update.apply();

        // Write updated state into header
        hdr.scsm.chain_idx = meta.new_chain_idx;
        hdr.scsm.prev_node = meta.this_node;
        hdr.scsm.tau       = meta.new_tau;

        // Step 6: egress verification at S6
        if (is_egress_node.apply().hit) {
            egress_verify.apply();
            // Strip SCSM tag before delivering to H2 (compliant path only)
            if (meta.violation == 0) {
                hdr.ethernet.ether_type = hdr.scsm.inner_ether_type;
                hdr.scsm.setInvalid();
            }
        }

        // Step 7: forward (compliant and violation packets alike)
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
