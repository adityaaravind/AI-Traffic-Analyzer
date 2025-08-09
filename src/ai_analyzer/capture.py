import datetime
from typing import Optional, Tuple, Dict, Any, List


def _safe_import_pyshark():
    try:
        import pyshark  # type: ignore
        return pyshark
    except Exception as e:
        raise RuntimeError(
            "pyshark is required to capture or read pcap files. "
            "Please install it via requirements.txt"
        ) from e


def capture_packets(
    pcap_path: Optional[str],
    duration: Optional[int],
    iface: Optional[str],
    capture_filter: Optional[str],
) -> Tuple[list, Dict[str, Any]]:
    """
    Returns (packets, capture_info)
    packets: list of pyshark packet objects
    capture_info: metadata about how capture was performed
    """
    pyshark = _safe_import_pyshark()
    packets: List[Any] = []
    info: Dict[str, Any] = {
        "mode": None,
        "start_time": datetime.datetime.utcnow().isoformat() + "Z",
        "end_time": None,
        "iface": iface,
        "filter": capture_filter,
        "pcap": pcap_path,
    }

    if pcap_path:
        # ---------- Offline capture from PCAP ----------
        info["mode"] = "offline"
        cap = pyshark.FileCapture(pcap_path)  # type: ignore
        try:
            for pkt in cap:
                packets.append(pkt)
        finally:
            try:
                cap.close()
            except Exception:
                pass
    else:
        # ---------- Live capture with hard stop via tshark (-a duration:N) ----------
        info["mode"] = "live"
        if not iface:
            raise ValueError("Live capture requested but --iface not provided.")
        timeout = duration if duration and duration > 0 else 10

        # Force tshark to exit on its own after N seconds to avoid pyshark timeout quirks.
        # We keep args broadly compatible across pyshark versions.
        if capture_filter:
            cap = pyshark.LiveCapture(
                interface=iface,
                bpf_filter=capture_filter,
                custom_parameters=["-a", f"duration:{timeout}"],
            )  # type: ignore
        else:
            cap = pyshark.LiveCapture(
                interface=iface,
                custom_parameters=["-a", f"duration:{timeout}"],
            )  # type: ignore

        try:
            # Iterate packets; tshark will terminate due to the -a duration limit.
            for pkt in cap:
                packets.append(pkt)
        finally:
            try:
                cap.close()
            except Exception:
                pass

    info["end_time"] = datetime.datetime.utcnow().isoformat() + "Z"
    info["packet_count"] = len(packets)
    return packets, info
