# log_parser.py

import re
import sys
from pathlib import Path

BLOCK_SPLIT = re.compile(r"\n(?=192\.168)")
AUTH_RE = re.compile(r'authorizedUserId: "([^"]+)"')


def load_blocks(file_path: str):
    text = Path(file_path).read_text()
    return BLOCK_SPLIT.split(text)


def parse_block(block: str):
    lines = block.strip().split("\n")
    if not lines:
        return None, []
    ip = lines[0].replace(":", "").strip()
    reqs = lines[1:]
    return ip, reqs


def analyze_requests(requests):
    api_calls = [r for r in requests if "/api/" in r]
    machine_calls = [r for r in requests if "machine/status" in r]

    suspicious_reasons = []

    # Flags
    high_volume = len(api_calls) > 15
    heavy_enum = len(machine_calls) >= 100

    if high_volume:
        suspicious_reasons.append("High API call volume (>15)")
    if heavy_enum:
        suspicious_reasons.append("Rapid machine status enumeration (>=100)")

    # Suspicion score = weighted
    score = (len(api_calls) * 1) + (len(machine_calls) * 2)

    return suspicious_reasons, api_calls, machine_calls, score


def extract_user_id(requests):
    for line in requests:
        m = AUTH_RE.search(line)
        if m:
            return m.group(1)
    return None


def main(log_path: str):
    blocks = load_blocks(log_path)

    most_suspicious = None  # store tuple: (score, ip, data)

    for block in blocks:
        if not block.strip():
            continue

        ip, reqs = parse_block(block)
        if not ip:
            continue

        suspicious_reasons, api_calls, machine_calls, score = analyze_requests(reqs)
        user_id = extract_user_id(reqs)

        # Only consider IPs with at least SOME suspicious signs
        if suspicious_reasons:
            if most_suspicious is None or score > most_suspicious[0]:
                most_suspicious = (score, ip, user_id, suspicious_reasons, len(api_calls), len(machine_calls))

    # Print only the most suspicious IP
    if most_suspicious:
        score, ip, user_id, reasons, api_count, machine_count = most_suspicious

        print("=== MOST SUSPICIOUS ACTIVITY DETECTED ===")
        print(f"IP: {ip}")
        if user_id:
            print(f"User ID: {user_id}")
        print(f"Suspicion score: {score}")
        for reason in reasons:
            print(f" - {reason}")
        print(f"API calls: {api_count}")
        print(f"Machine status calls: {machine_count}")
        print()
    else:
        print("No suspicious activity found.")


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "./web_activity.log"
    main(log_path)
