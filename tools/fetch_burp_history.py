#!/usr/bin/env python3
"""
fetch_burp_history.py — Pull all HTTP history from the Aegis360 Burp extension
                         (running on port 9997) and dump decoded req/resp to JSON/stdout.

Usage:
  python3 fetch_burp_history.py                    # all history
  python3 fetch_burp_history.py --host every.io    # filtered by hostname
  python3 fetch_burp_history.py --limit 50         # last N items
  python3 fetch_burp_history.py --out history.json # save to file
  python3 fetch_burp_history.py --decode            # print decoded req/resp
"""

import argparse
import base64
import json
import sys
import urllib.request
import urllib.error

BURP_EXT_PORT = 9997
BURP_EXT_BASE = f"http://127.0.0.1:{BURP_EXT_PORT}"


def fetch(host_filter=None, limit=1000):
    params = f"limit={limit}"
    if host_filter:
        params += f"&host={host_filter}"
    url = f"{BURP_EXT_BASE}/history?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.URLError as e:
        print(f"[!] Cannot reach Burp extension on port {BURP_EXT_PORT}: {e}", file=sys.stderr)
        print("[!] Make sure the extension is loaded in Burp → Extensions → Add → Python", file=sys.stderr)
        sys.exit(1)


def check_status():
    try:
        with urllib.request.urlopen(f"{BURP_EXT_BASE}/status", timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def decode_item(item):
    """Return item with base64 fields decoded to UTF-8 strings."""
    out = dict(item)
    for field in ("request_b64", "response_b64"):
        raw_b64 = item.get(field, "")
        if raw_b64:
            try:
                out[field.replace("_b64", "_decoded")] = base64.b64decode(raw_b64).decode("utf-8", errors="replace")
            except Exception:
                out[field.replace("_b64", "_decoded")] = "<decode error>"
    return out


def print_decoded(items):
    for i, item in enumerate(items, 1):
        print(f"\n{'='*70}")
        print(f"[{i}] {item['method']} {item['url']}  →  HTTP {item['status']}")
        print(f"     Host: {item['host']}:{item['port']}  |  MIME: {item.get('mime_type','?')}  |  Highlight: {item.get('highlight','')}  Comment: {item.get('comment','')}")
        print(f"\n--- REQUEST ---")
        req = base64.b64decode(item.get("request_b64", "")).decode("utf-8", errors="replace") if item.get("request_b64") else ""
        print(req[:2000] + ("...[truncated]" if len(req) > 2000 else ""))
        print(f"\n--- RESPONSE ---")
        resp = base64.b64decode(item.get("response_b64", "")).decode("utf-8", errors="replace") if item.get("response_b64") else ""
        print(resp[:2000] + ("...[truncated]" if len(resp) > 2000 else ""))


def main():
    ap = argparse.ArgumentParser(description="Fetch Burp HTTP history from Aegis360 extension")
    ap.add_argument("--host", default=None, help="Filter by hostname substring")
    ap.add_argument("--limit", type=int, default=1000, help="Max items to fetch (default 1000)")
    ap.add_argument("--out", default=None, help="Save raw JSON output to file")
    ap.add_argument("--decode", action="store_true", help="Print decoded request/response text")
    ap.add_argument("--status", action="store_true", help="Just check extension health")
    args = ap.parse_args()

    if args.status:
        st = check_status()
        if st:
            print(f"[+] Extension healthy — {st.get('history_count', '?')} items in history")
        else:
            print("[-] Extension not reachable on port 9997")
        return

    print(f"[*] Fetching Burp HTTP history (host={args.host or 'all'}, limit={args.limit})...")
    data = fetch(host_filter=args.host, limit=args.limit)

    if not data.get("success"):
        print(f"[!] Extension returned error: {data.get('error')}", file=sys.stderr)
        sys.exit(1)

    items = data.get("items", [])
    total = data.get("total_in_history", 0)
    print(f"[+] {len(items)} items returned (total in Burp history: {total})")

    # Summary table
    print(f"\n{'#':<5} {'METHOD':<8} {'STATUS':<7} {'HOST':<35} URL")
    print("-" * 90)
    for i, item in enumerate(items, 1):
        url_short = item["url"][:60] + ("..." if len(item["url"]) > 60 else "")
        print(f"{i:<5} {item['method']:<8} {item['status']:<7} {item['host'][:34]:<35} {url_short}")

    if args.decode:
        print_decoded(items)

    if args.out:
        # Add decoded fields before saving
        decoded_items = [decode_item(it) for it in items]
        with open(args.out, "w") as f:
            json.dump({"total_in_history": total, "returned": len(items), "items": decoded_items}, f, indent=2)
        print(f"\n[+] Saved to {args.out}")


if __name__ == "__main__":
    main()
