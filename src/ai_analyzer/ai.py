import json
import time
import random
import requests
from typing import Dict, Any, Tuple

def _limit_lines(pairs, n):
    return pairs[:n] if isinstance(pairs, list) else []

def _build_prompt(metrics: Dict[str, Any]) -> str:
    # keep prompts small to reduce tokens and rate pressure
    protos = _limit_lines(metrics.get("protocols", []), 15)
    ips    = _limit_lines(metrics.get("top_ips", []), 10)
    ports  = _limit_lines(metrics.get("top_ports", []), 10)
    flags  = _limit_lines(metrics.get("tcp_flags", []), 10)

    proto_lines = [f"- {p}: {c}" for p, c in protos]
    ip_lines    = [f"- {ip}: {c}" for ip, c in ips]
    port_lines  = [f"- {port}: {c}" for port, c in ports]
    flag_lines  = [f"- {f}: {c}" for f, c in flags]

    prompt = f"""
You are a seasoned network security analyst. Analyze the following traffic snapshot and describe notable patterns or anomalies.

Return strictly:
Summary: 3–6 bullet points
Tags: short, comma-separated (≤8), no sentences

Metrics:
Total packets: {metrics.get("total_packets")}
Total bytes: {metrics.get("total_bytes")}

Protocol breakdown:
{chr(10).join(proto_lines)}

Top talkers (IPs):
{chr(10).join(ip_lines)}

Top ports:
{chr(10).join(port_lines)}

TCP flags:
{chr(10).join(flag_lines)}
""".strip()
    return prompt

def _post_with_retries(url: str, headers: dict, payload: dict, max_retries: int = 5) -> Tuple[bool, str]:
    """
    Returns (ok, text_or_error). On success -> (True, content_text).
    On failure -> (False, human_readable_error).
    """
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
            # 429 / 5xx retryable
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                # Honor Retry-After if present; otherwise exponential backoff with jitter
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait_s = max(1, int(float(retry_after)))
                    except Exception:
                        wait_s = 2 ** attempt + random.uniform(0, 0.5)
                else:
                    wait_s = 2 ** attempt + random.uniform(0, 0.5)
                if attempt < max_retries - 1:
                    time.sleep(wait_s)
                    continue
            resp.raise_for_status()
            data = resp.json()
            return True, data["choices"][0]["message"]["content"]
        except requests.RequestException as e:
            # last attempt -> return the error
            if attempt == max_retries - 1:
                # include status code message if available
                try:
                    msg = resp.text  # type: ignore[name-defined]
                except Exception:
                    msg = str(e)
                return False, msg
            # backoff for network errors too
            time.sleep(2 ** attempt + random.uniform(0, 0.5))
    return False, "Unknown error"

def _parse_ai(text: str) -> Dict[str, Any]:
    summary_bullets = []
    tags = []
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    in_summary = False
    for line in lines:
        low = line.lower()
        if low.startswith("summary"):
            in_summary = True
            continue
        if low.startswith("tags"):
            in_summary = False
            parts = line.split(":", 1)
            tags_text = parts[1] if len(parts) == 2 else line
            tags = [t.strip() for t in tags_text.replace("Tags", "").replace("tags", "").split(",") if t.strip()]
            continue
        if in_summary:
            line = line.lstrip("-•* ").strip()
            if line:
                summary_bullets.append(line)
    if not tags:
        if lines and "," in lines[-1] and len(lines) <= 10:
            tags = [t.strip() for t in lines[-1].split(",") if t.strip()]
    return {"summary_bullets": summary_bullets[:6], "tags": tags[:8]}

def generate_ai_summary(metrics: Dict[str, Any], api_key: str, model: str) -> Dict[str, Any]:
    prompt = _build_prompt(metrics)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a helpful cybersecurity assistant."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    ok, text_or_error = _post_with_retries("https://api.openai.com/v1/chat/completions", headers, payload, max_retries=5)
    if not ok:
        # Show a single friendly line in the report, not a stack trace
        return {"summary_bullets": [f"AI request failed (rate limited or temporarily unavailable). Details: {text_or_error[:200]}"], "tags": []}
    return _parse_ai(text_or_error)
