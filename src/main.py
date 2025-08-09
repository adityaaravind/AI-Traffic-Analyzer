#!/usr/bin/env python3
import argparse
import os
from dotenv import load_dotenv
from ai_analyzer.capture import capture_packets
from ai_analyzer.metrics import compute_metrics
from ai_analyzer.ai import generate_ai_summary
from ai_analyzer.report import render_report

def parse_args():
    p = argparse.ArgumentParser(
        description="ai-traffic-analyzer-mini: Minimal AI-powered network traffic analyzer"
    )
    p.add_argument("--pcap", type=str, help="Path to pcap file for offline analysis")
    p.add_argument("--duration", type=int, help="Live capture duration in seconds", default=None)
    p.add_argument("--iface", type=str, help="Network interface name for live capture", default=None)
    p.add_argument("--filter", type=str, help="Capture filter (BPF), e.g., 'tcp or udp or icmp'", default=None)
    p.add_argument("--out", type=str, help="Output HTML report path", default="report.html")
    return p.parse_args()

def main():
    args = parse_args()

    # .env
    load_dotenv()
    openai_api_key = os.getenv("OPENAI_API_KEY")
    openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    packets, capture_info = capture_packets(
        pcap_path=args.pcap,
        duration=args.duration,
        iface=args.iface,
        capture_filter=args.filter
    )

    metrics = compute_metrics(packets)

    ai_disabled = False
    ai_result = {"summary_bullets": [], "tags": []}
    if not openai_api_key:
        print("AI disabled")
        ai_disabled = True
    else:
        ai_result = generate_ai_summary(metrics, openai_api_key, openai_model)

    html = render_report(metrics, ai_result, ai_disabled, capture_info)

    out_path = args.out
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Wrote report to {out_path}")

if __name__ == "__main__":
    main()
