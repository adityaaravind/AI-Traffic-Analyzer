from collections import Counter, defaultdict
from typing import Dict, Any

def _get_frame_len(pkt) -> int:
    # Try several fields to get frame length in bytes
    for path in ["frame_info.len", "length", "ip.len"]:
        try:
            obj = pkt
            for part in path.split("."):
                obj = getattr(obj, part)
            val = int(str(obj))
            if val >= 0:
                return val
        except Exception:
            continue
    return 0

def _get_proto(pkt) -> str:
    try:
        return str(pkt.highest_layer)
    except Exception:
        return "UNKNOWN"

def _get_ips(pkt):
    src = dst = None
    try:
        if hasattr(pkt, "ip"):
            src = getattr(pkt.ip, "src", None)
            dst = getattr(pkt.ip, "dst", None)
        elif hasattr(pkt, "ipv6"):
            src = getattr(pkt.ipv6, "src", None)
            dst = getattr(pkt.ipv6, "dst", None)
    except Exception:
        pass
    return src, dst

def _get_ports(pkt):
    s = d = None
    try:
        if hasattr(pkt, "tcp"):
            s = getattr(pkt.tcp, "srcport", None)
            d = getattr(pkt.tcp, "dstport", None)
        elif hasattr(pkt, "udp"):
            s = getattr(pkt.udp, "srcport", None)
            d = getattr(pkt.udp, "dstport", None)
    except Exception:
        pass
    return s, d

def _get_tcp_flags(pkt):
    d = defaultdict(int)
    if hasattr(pkt, "tcp"):
        try:
            # Individual boolean flags exist in pyshark (as "1" or "0")
            for name, key in [
                ("fin", "flags_fin"),
                ("syn", "flags_syn"),
                ("rst", "flags_reset"),
                ("psh", "flags_push"),
                ("ack", "flags_ack"),
                ("urg", "flags_urg"),
                ("ece", "flags_ece"),
                ("cwr", "flags_cwr"),
            ]:
                val = getattr(pkt.tcp, key, None)
                if val is not None and str(val) == "1":
                    d[name.upper()] += 1
        except Exception:
            pass
    return d

def compute_metrics(packets) -> Dict[str, Any]:
    total_packets = 0
    total_bytes = 0
    protocols = Counter()
    ip_counter = Counter()
    port_counter = Counter()
    tcp_flags = Counter()

    for pkt in packets:
        total_packets += 1
        total_bytes += _get_frame_len(pkt)

        proto = _get_proto(pkt)
        protocols[proto] += 1

        src, dst = _get_ips(pkt)
        if src:
            ip_counter[src] += 1
        if dst:
            ip_counter[dst] += 1

        sp, dp = _get_ports(pkt)
        if sp:
            port_counter[str(sp)] += 1
        if dp:
            port_counter[str(dp)] += 1

        flags = _get_tcp_flags(pkt)
        for k, v in flags.items():
            tcp_flags[k] += v

    metrics = {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocols": protocols.most_common(),
        "top_ips": ip_counter.most_common(10),
        "top_ports": port_counter.most_common(10),
        "tcp_flags": tcp_flags.most_common(),
    }
    return metrics
