#!/usr/bin/env python3
"""
SCSM SDN Controller — VSlice/SCSM PoC
Spec: Software Specification Document §4

Connects to BMv2 switches via P4Runtime (gRPC) and populates all
match-action tables for both service chains C1 and C2.

Usage:
    python3 controller.py [--topo topology.json] [--test <scenario|all>]
    python3 controller.py --tau-dump
"""

import argparse
import json
import sys
import os
from typing import Optional

# ── P4Runtime imports ──────────────────────────────────────────────────────
sys.path.append('/home/p4/tutorials/utils')
from p4runtime_lib.bmv2 import Bmv2SwitchConnection
from p4runtime_lib.helper import P4InfoHelper
import p4runtime_lib.helper as helper
import grpc

# ──────────────────────────────────────────────────────────────────────────
# Constants — must match scsm.p4
# ──────────────────────────────────────────────────────────────────────────
UNDEFINED_NODE  = 0xFF          # ⊥
ETHERTYPE_SCSM  = 0x88B5
ETHERTYPE_IPV4  = 0x0800
SLICE_ID        = 1
P4INFO_PATH     = 'build/scsm.p4.p4info.txtpb'
BMV2_JSON_PATH  = 'build/scsm.json'
MASK32          = 0xFFFFFFFF

# gRPC port base: switch s{n} listens on 50050+n
def grpc_port(node_id: int) -> int:
    if node_id == 99:
        return 50057  # Mininet assigned the 7th switch to 50057
    return 50050 + node_id

# ──────────────────────────────────────────────────────────────────────────
# τ computation — mirrors tau_update action in scsm.p4 exactly
# ──────────────────────────────────────────────────────────────────────────
def compute_tau(tau: int, node_id: int, chain_idx: int, key: int) -> int:
    return (tau ^ key ^ ((node_id & 0xFF) << 8) ^ (chain_idx & 0xFF)) & MASK32

def compute_tau_chain(seed: int, path: list, service_chain: list,
                      hop_keys: dict) -> tuple:
    tau, idx, hops = seed, 0, []
    for node in path:
        key = hop_keys.get(str(node), 0xDEADBEEF)
        if idx < len(service_chain) and service_chain[idx] == node:
            idx += 1
        tau = compute_tau(tau, node, idx, key)
        hops.append({"node": node, "chain_idx": idx, "tau": tau})
    return tau, hops

# ──────────────────────────────────────────────────────────────────────────
# Controller
# ──────────────────────────────────────────────────────────────────────────
class SCSMController:

    def __init__(self, topo_path: str):
        with open(topo_path) as f:
            self.topo = json.load(f)

        self.slc        = self.topo["slice"]
        self.node_ids   = self.topo["node_ids"]           # "s1" → 1
        self.id_to_name = {v: k for k, v in self.node_ids.items()}

        # Build switch info keyed by node_id
        self.switches: dict = {}
        for sw_name, info in self.topo["switches"].items():
            nid = self.node_ids.get(sw_name)
            if nid is None:
                continue
            self.switches[nid] = {"name": sw_name, **info}

        self.p4info_helper = P4InfoHelper(P4INFO_PATH)
        self.runtimes: dict = {}   # node_id → Bmv2SwitchConnection

        # Pre-compute final τ for each chain (used in egress_verify)
        self._chain_final_tau = {}
        for cname, cdata in self.slc["service_chains"].items():
            seed  = int(self.slc["tau_seeds"][cname], 16)
            keys  = {k: int(v, 16) for k, v in self.slc["hop_keys"][cname].items()}
            path  = self.slc["paths"][cdata["path"]]
            chain = cdata["chain"]
            final_tau, _ = compute_tau_chain(seed, path, chain, keys)
            self._chain_final_tau[cname] = final_tau
            print(f"[init] {cname} final τ = 0x{final_tau:08X}")

    # ── Connection ──────────────────────────────────────────────────────
    def connect(self):
        for node_id, sw in self.switches.items():
            name = sw["name"]
            port = grpc_port(node_id)
            print(f"[ctrl] connecting to {name} @ 127.0.0.1:{port}")
            try:
                rt = Bmv2SwitchConnection(
                    name=name,
                    address=f"127.0.0.1:{port}",
                    device_id=node_id - 1,
                    proto_dump_file=f"logs/{name}-p4runtime.txt"
                )
                rt.MasterArbitrationUpdate()
                rt.SetForwardingPipelineConfig(
                    p4info=self.p4info_helper.p4info,
                    bmv2_json_file_path=BMV2_JSON_PATH
                )
                self.runtimes[node_id] = rt
                print(f"[ctrl]   ✓ {name} pipeline loaded")
            except grpc.RpcError as e:
                print(f"[warn] {name}: gRPC error — {e.details()}")

    # ── Write helper ─────────────────────────────────────────────────────
    def _write(self, node_id: int, table: str,
               match_fields: dict, action: str, params: dict, priority: int = 0):
        rt = self.runtimes.get(node_id)
        if rt is None:
            return
            
        try:
            entry = self.p4info_helper.buildTableEntry(
                table_name=table,
                match_fields=match_fields,
                action_name=action,
                action_params=params,
                priority=priority
            )
            rt.WriteTableEntry(entry)
        except grpc.RpcError as e:
            # Safely catch switch rejections (like duplicate entries for overlapping chains)
            print(f"    [warn] S{node_id} rejected {table}: {e.details()}")
        except Exception as e:
            print(f"    [warn] Script builder failed on {table}: {e}")

    # ── Provisioning ─────────────────────────────────────────────────────
    def provision_all(self):
        os.makedirs("logs", exist_ok=True)

        # node_config: port → node_id for every switch
        for node_id, sw in self.switches.items():
            self._install_node_config(node_id)

        # Per-chain rules
        for cname, cdata in self.slc["service_chains"].items():
            print(f"\n[ctrl] provisioning chain {cname} …")
            self._provision_chain(cname, cdata)

        print("\n[ctrl] all tables provisioned.")

    def _install_node_config(self, node_id: int):
        ports = [1, 2, 3, 4] if node_id == 2 else [1, 2, 3]
        for port in ports:
            self._write(
                node_id,
                table="SCSMIngress.node_config",
                match_fields={"std_meta.ingress_port": port},
                action="SCSMIngress.set_node_id",
                params={"node_id": node_id}
            )

    def _provision_chain(self, cname: str, cdata: dict):
        cid       = cdata["id"]
        chain     = cdata["chain"]          # ordered service nodes
        path      = self.slc["paths"][cdata["path"]]
        edges     = self.slc["authorized_edges"]
        ing_node  = path[0]                 # S1
        egr_node  = path[-1]                # S6
        seed      = int(self.slc["tau_seeds"][cname], 16)
        hop_keys  = {k: int(v, 16) for k, v in self.slc["hop_keys"][cname].items()}
        chain_len = len(chain)
        final_tau = self._chain_final_tau[cname]

        # ── ingress_init at S1 ───────────────────────────────────────
        # Dynamically find which port S1 uses to connect to H1
        ing_name = self.id_to_name.get(ing_node)
        p_h1 = self._get_link_port(ing_name, "h1")

        self._write(
            ing_node,
            table="SCSMIngress.ingress_init",
            match_fields={
                "std_meta.ingress_port": p_h1
            },
            action="SCSMIngress.init_tag",
            params={
                "slice_id":   SLICE_ID,
                "chain_id":   cid,
                "tau0":       seed,
                "inner_etype": ETHERTYPE_IPV4
            },
            priority=1  
        )

        # ── predecessor_check for every node on this path ────────────
        for node in path:
            # authorized predecessors for this node in the slice
            preds = [v for [v, u] in edges if u == node]
            if node == ing_node:
                preds.append(UNDEFINED_NODE)   # ⊥ valid at ingress

            for pred in preds:
                self._write(
                    node,
                    table="SCSMIngress.predecessor_check",
                    match_fields={
                        "hdr.scsm.slice_id":  SLICE_ID,
                        "meta.this_node":     node,
                        "hdr.scsm.prev_node": pred
                    },
                    action="SCSMIngress.topology_ok",
                    params={}
                )

        # ── chain_step: increment when node == chain[i] ──────────────
        for i, svc_node in enumerate(chain):
            self._write(
                svc_node,
                table="SCSMIngress.chain_step",
                match_fields={
                    "hdr.scsm.chain_id":  cid,
                    "meta.this_node":     svc_node,
                    "hdr.scsm.chain_idx": i
                },
                action="SCSMIngress.increment_chain",
                params={}
            )

        # ── tau_update key material per hop ──────────────────────────
        for node in path:
            key_mat = hop_keys.get(str(node), 0xDEADBEEF)
            self._write(
                node,
                table="SCSMIngress.tau_update",
                match_fields={
                    "hdr.scsm.slice_id": SLICE_ID,
                    "meta.this_node":    node
                },
                action="SCSMIngress.update_tau",
                params={"key_material": key_mat}
            )

        # ── is_egress_node + egress_verify at S6 ─────────────────────
        self._write(
            egr_node,
            table="SCSMIngress.is_egress_node",
            match_fields={
                "hdr.scsm.slice_id": SLICE_ID,
                "meta.this_node":    egr_node
            },
            action="SCSMIngress.egress_compliant",
            params={}
        )
        self._write(
            egr_node,
            table="SCSMIngress.egress_verify",
            match_fields={
                "hdr.scsm.slice_id":  SLICE_ID,
                "meta.this_node":     egr_node,
                "hdr.scsm.chain_idx": chain_len,
                "meta.violation":     0,
                "meta.new_tau":       final_tau
            },
            action="SCSMIngress.egress_compliant",
            params={}
        )

        # ── forwarding: dst MAC of H2 → egress port ──────────────────
        h2_mac = self.topo["hosts"]["h2"]["mac"]
        
        fw_provisioned = set()  # Track provisioned forwarding rules to prevent duplicates
        
        for node in path:
            # --- CUSTOM HAIRPIN LOGIC FOR S2 in C1 ---
            # --- CUSTOM HAIRPIN LOGIC FOR S2 in C1 ---
            if cname == "C1" and node == 2:
                if 2 not in fw_provisioned:
                    # Dynamically look up actual wiring ports
                    p_s1  = self._get_link_port("s2", "s1")
                    p_fw  = self._get_link_port("s2", "h_fw")
                    p_ids = self._get_link_port("s2", "h_ids")
                    p_s3  = self._get_link_port("s2", "s3")

                    # Arrives from S1 -> Send to NFFW1
                    self._write(2, table="SCSMIngress.forwarding",
                                match_fields={
                                    "hdr.ethernet.dst_addr": h2_mac, 
                                    "std_meta.ingress_port": (p_s1, 0x1FF)
                                },
                                action="SCSMIngress.forward", params={"port": p_fw}, priority=10)
                    
                    # Arrives from NFFW1 -> Send to NFIDS1
                    self._write(2, table="SCSMIngress.forwarding",
                                match_fields={
                                    "hdr.ethernet.dst_addr": h2_mac, 
                                    "std_meta.ingress_port": (p_fw, 0x1FF)
                                },
                                action="SCSMIngress.forward", params={"port": p_ids}, priority=10)
                    
                    # Arrives from NFIDS1 -> Send to S3
                    self._write(2, table="SCSMIngress.forwarding",
                                match_fields={
                                    "hdr.ethernet.dst_addr": h2_mac, 
                                    "std_meta.ingress_port": (p_ids, 0x1FF)
                                },
                                action="SCSMIngress.forward", params={"port": p_s3}, priority=10)
                    fw_provisioned.add(2)
                continue  # Skip standard forwarding for S2
                
            # --- STANDARD FORWARDING LOGIC ---
            if node in fw_provisioned:
                continue

            out_port = self._next_hop_port(node, egr_node, path)
            if out_port is not None:
                self._write(
                    node,
                    table="SCSMIngress.forwarding",
                    match_fields={
                        "hdr.ethernet.dst_addr": h2_mac
                    },
                    action="SCSMIngress.forward",
                    params={"port": out_port},
                    priority=1  
                )
                fw_provisioned.add(node)

    # ── Utilities ─────────────────────────────────────────────────────────
    def _get_link_port(self, src_name: str, dst_name: str) -> int:
        """Finds the physical port on src_name that connects to dst_name."""
        for link in self.topo["links"]:
            a, b = link[0], link[1]
            na, pa = (a.split("-p") + [None])[:2] if "-p" in a else (a, None)
            nb, pb = (b.split("-p") + [None])[:2] if "-p" in b else (b, None)
            if na == src_name and nb == dst_name and pa:
                return int(pa)
            if nb == src_name and na == dst_name and pb:
                return int(pb)
        return -1
    
    def _next_hop_port(self, src_node: int, dst_node: int,
                       path: list) -> Optional[int]:
        """Return the port on src_node that leads toward the next hop in path."""
        src_name = self.id_to_name.get(src_node)
        if src_name is None:
            return None
        # find next node in path after src_node
        try:
            idx = path.index(src_node)
        except ValueError:
            return None
        if idx + 1 >= len(path):
            # src_node IS the egress — port to H2 is port 1
            return 1
        next_node = path[idx + 1]
        next_name = self.id_to_name.get(next_node)

        for link in self.topo["links"]:
            a, b = link[0], link[1]
            na, pa = (a.split("-p") + [None])[:2] if "-p" in a else (a, None)
            nb, pb = (b.split("-p") + [None])[:2] if "-p" in b else (b, None)
            if na == src_name and nb == next_name and pa:
                return int(pa)
            if nb == src_name and na == next_name and pb:
                return int(pb)
        return None

    # ── Test scenario analysis ────────────────────────────────────────────
    def run_test_scenario(self, scenario_key: str):
        scenario = self.topo["test_scenarios"].get(scenario_key)
        if scenario is None:
            print(f"[test] unknown scenario: {scenario_key}")
            return

        print(f"\n{'='*60}")
        print(f"TEST  : {scenario_key}")
        print(f"DESC  : {scenario['description']}")
        print(f"PATH  : {scenario['path']}")
        print(f"EXPECT: {scenario['expected_outcome']}")

        cname    = scenario["chain"]
        cdata    = self.slc["service_chains"][cname]
        chain    = cdata["chain"]
        edges    = self.slc["authorized_edges"]
        path     = scenario["path"]
        seed     = int(self.slc["tau_seeds"][cname], 16)
        keys     = {k: int(v, 16) for k, v in self.slc["hop_keys"][cname].items()}

        print("\n  Trace:")
        prev   = UNDEFINED_NODE
        ok     = True
        tau    = seed
        idx    = 0

        for node in path:
            preds = [v for [v, u] in edges if u == node]
            if node == path[0]:
                preds.append(UNDEFINED_NODE)

            if prev not in preds:
                print(f"    node {node:2d}: ✗ TOPOLOGY VIOLATION "
                      f"(prev={prev} ∉ {preds})")
                ok = False
                # flag set but continue tracing (spec: don't drop)
            else:
                print(f"    node {node:2d}: ✓ topology OK")

            key = keys.get(str(node), 0xDEADBEEF)
            if idx < len(chain) and chain[idx] == node:
                idx += 1
            tau = compute_tau(tau, node, idx, key)
            prev = node

        k = len(chain)
        if not ok:
            print(f"\n  → Violation flag carried to egress.")
        elif idx < k:
            print(f"\n  → CHAIN BYPASS: chain_idx={idx} < k={k}")
        else:
            exp = self._chain_final_tau[cname]
            if tau == exp:
                print(f"\n  → COMPLIANT ✓  τ=0x{tau:08X}")
            else:
                print(f"\n  → TAU MISMATCH: got 0x{tau:08X} expected 0x{exp:08X}")

        print('='*60)

    def dump_tau_chains(self):
        print("\n[ctrl] τ chain summary:")
        for cname, cdata in self.slc["service_chains"].items():
            seed  = int(self.slc["tau_seeds"][cname], 16)
            keys  = {k: int(v, 16) for k, v in self.slc["hop_keys"][cname].items()}
            path  = self.slc["paths"][cdata["path"]]
            chain = cdata["chain"]
            final, hops = compute_tau_chain(seed, path, chain, keys)
            print(f"\n  {cname} (id={cdata['id']})")
            for h in hops:
                print(f"    node {h['node']:2d}  chain_idx={h['chain_idx']}"
                      f"  τ=0x{h['tau']:08X}")
            print(f"    → final τ = 0x{final:08X}")

    def shutdown(self):
        for rt in self.runtimes.values():
            rt.shutdown()


# ──────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SCSM Controller — VSlice PoC")
    parser.add_argument("--topo", default="topology.json")
    parser.add_argument("--test", default="none",
                        choices=["none", "all",
                                 "scenario_1_compliant_P1",
                                 "scenario_1_compliant_P2",
                                 "scenario_2_chain_bypass",
                                 "scenario_3_topology_violation"])
    parser.add_argument("--tau-dump", action="store_true")
    args = parser.parse_args()

    ctrl = SCSMController(args.topo)

    if args.tau_dump:
        ctrl.dump_tau_chains()
        return

    try:
        ctrl.connect()
        ctrl.provision_all()

        if args.test == "all":
            for sc in ["scenario_1_compliant_P1", "scenario_1_compliant_P2",
                       "scenario_2_chain_bypass", "scenario_3_topology_violation"]:
                ctrl.run_test_scenario(sc)
        elif args.test != "none":
            ctrl.run_test_scenario(args.test)
    finally:
        ctrl.shutdown()


if __name__ == "__main__":
    main()