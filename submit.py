#!/usr/bin/env python3
"""
Client for the persistent faphouse_session.py worker.

Examples:
    python3 submit.py "https://faphouse2.com/videos/..."
    python3 submit.py --status
    python3 submit.py --health
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


DEFAULT_BASE = "http://127.0.0.1:8787"


def request_json(url: str, method: str = "GET", payload=None, timeout: int = 130):
    data = None
    headers = {"Accept": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw)
        except Exception:
            body = {"success": False, "error": raw or str(exc)}
        return exc.code, body
    except urllib.error.URLError as exc:
        return 0, {
            "success": False,
            "error": f"Cannot reach worker: {exc.reason}",
            "hint": "Is faphouse_session.py running under PM2?",
        }
    except TimeoutError:
        return 0, {
            "success": False,
            "error": "Request timed out",
            "hint": "The browser may still be starting or the extraction may be taking longer.",
        }


def print_json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a URL to the persistent Faphouse worker")
    parser.add_argument("url", nargs="?", help="Faphouse video URL")
    parser.add_argument("--base", default=DEFAULT_BASE, help="worker base URL")
    parser.add_argument("--status", action="store_true", help="show worker status")
    parser.add_argument("--health", action="store_true", help="show worker health")
    args = parser.parse_args()

    base = args.base.rstrip("/")

    if args.status:
        code, body = request_json(f"{base}/status")
        print_json(body)
        return 0 if code == 200 and body.get("success") else 1

    if args.health:
        code, body = request_json(f"{base}/health")
        print_json(body)
        return 0 if code == 200 and body.get("success") else 1

    if not args.url:
        parser.error("give a video URL, or use --status / --health")

    code, body = request_json(
        f"{base}/extract",
        method="POST",
        payload={"url": args.url},
        timeout=180,
    )

    print_json(body)

    if code == 0:
        return 1

    if body.get("error") == "SESSION_EXPIRED":
        print("\n❌ SESSION EXPIRED — the persistent browser is no longer logged in.", file=sys.stderr)
        return 2

    manifests = body.get("m3u8") or []
    if manifests:
        print("\n.m3u8 URLs:")
        for item in manifests:
            print(item)

    return 0 if body.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
