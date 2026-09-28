#!/usr/bin/env python3
"""
Persistent Faphouse browser worker.

- Uses Scrapling StealthyFetcher + Playwright, headless.
- Persists the browser profile in ./faphouse-profile.
- Loads ./cookie.json only when the existing profile is not logged in.
- Keeps one browser alive under PM2.
- Refreshes the site about every 10 minutes while idle.
- Exposes a localhost-only HTTP API so submit.py can send video URLs later.
- Extracts all observed .m3u8 URLs from network requests and page content.

Run:
    python3 faphouse_session.py

PM2:
    pm2 start faphouse_session.py --name faphouse --interpreter python3
    pm2 save

API:
    POST http://127.0.0.1:8787/extract
    {"url":"https://faphouse2.com/videos/..."}

    GET http://127.0.0.1:8787/status
"""

from __future__ import annotations

import argparse
import json
import logging
import queue
import re
import signal
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from scrapling.fetchers import StealthyFetcher
    from playwright.sync_api import Page
except Exception as exc:
    StealthyFetcher = None  # type: ignore
    Page = Any  # type: ignore
    IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
else:
    IMPORT_ERROR = ""

SITE_URL = "https://faphouse2.com"
SITE_HOST = "faphouse2.com"

BASE_DIR = Path(__file__).resolve().parent
COOKIE_FILE = BASE_DIR / "cookie.json"
PROFILE_DIR = BASE_DIR / "faphouse-profile"

API_HOST = "127.0.0.1"
API_PORT = 8787

KEEPALIVE_SECONDS = 10 * 60
NAVIGATION_TIMEOUT_MS = 60_000
EXTRACTION_SETTLE_SECONDS = 15
REQUEST_TIMEOUT_SECONDS = 120

LOGIN_RE = re.compile(r"\b(?:log\s*in|login|sign\s*in|sign\s*up)\b", re.I)
M3U8_RE = re.compile(
    r"https?://[^\s\"'<>\\]+?\.m3u8(?:\?[^\s\"'<>\\]+)?",
    re.I,
)


@dataclass
class Job:
    url: str
    done: threading.Event
    result: Optional[Dict[str, Any]] = None


class State:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.page: Optional[Page] = None
        self.browser_ready = False
        self.logged_in = False
        self.session_source = "unknown"
        self.session_detail = ""
        self.last_session_check = 0.0
        self.last_keepalive = 0.0
        self.last_job_at = 0.0
        self.current_url = ""
        self.busy = False
        self.last_result: Optional[Dict[str, Any]] = None
        self.last_error = ""

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "browserReady": self.browser_ready,
                "loggedIn": self.logged_in,
                "sessionSource": self.session_source,
                "sessionDetail": self.session_detail,
                "lastSessionCheck": iso_or_none(self.last_session_check),
                "lastKeepalive": iso_or_none(self.last_keepalive),
                "lastJobAt": iso_or_none(self.last_job_at),
                "currentUrl": self.current_url,
                "busy": self.busy,
                "lastResult": self.last_result,
                "lastError": self.last_error,
                "profile": str(PROFILE_DIR),
                "cookieFile": str(COOKIE_FILE),
                "keepaliveSeconds": KEEPALIVE_SECONDS,
            }


STATE = State()
JOBS: "queue.Queue[Job]" = queue.Queue(maxsize=32)
STOP = threading.Event()
API_SERVER: Optional[ThreadingHTTPServer] = None


def iso_or_none(ts: float) -> Optional[str]:
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def log_session(
    logged_in: bool,
    source: str,
    detail: str,
) -> None:
    with STATE.lock:
        STATE.logged_in = logged_in
        STATE.session_source = source
        STATE.session_detail = detail
        STATE.last_session_check = time.time()

    if logged_in:
        logging.info("✅ SESSION ALIVE — %s (%s)", detail, source)
    else:
        logging.error("❌ SESSION DEAD — %s", detail)


def normalize_m3u8(value: str) -> str:
    value = value.replace("\\/", "/")
    value = value.replace("&amp;", "&")
    return value.strip(" \t\r\n\"'<>),;]")


def add_m3u8(out: set[str], value: str) -> None:
    value = normalize_m3u8(value)
    if ".m3u8" not in value.lower():
        return
    if value.startswith("http://") or value.startswith("https://"):
        out.add(value)


def extract_m3u8_from_text(text: str) -> List[str]:
    found: set[str] = set()
    if not text:
        return []
    for match in M3U8_RE.finditer(text):
        add_m3u8(found, match.group(0))
    return sorted(found)


def sanitize_cookie(cookie: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Convert common browser-export cookie formats into Playwright format.
    Supports:
      name, value, domain, path, expirationDate, sameSite, secure, httpOnly
    """
    name = cookie.get("name")
    value = cookie.get("value")

    if name is None or value is None:
        return None

    out: Dict[str, Any] = {
        "name": str(name),
        "value": str(value),
        "path": str(cookie.get("path") or "/"),
    }

    domain = cookie.get("domain")
    if domain:
        out["domain"] = str(domain)
    else:
        out["url"] = SITE_URL

    expiration = cookie.get("expirationDate", cookie.get("expires"))
    if expiration not in (None, "", 0, "0"):
        try:
            exp = float(expiration)
            if exp > 0:
                out["expires"] = exp
        except (TypeError, ValueError):
            pass

    same_site = cookie.get("sameSite")
    if isinstance(same_site, str):
        mapping = {
            "no_restriction": "None",
            "none": "None",
            "lax": "Lax",
            "strict": "Strict",
        }
        out["sameSite"] = mapping.get(same_site.lower(), "Lax")

    if "secure" in cookie:
        out["secure"] = bool(cookie["secure"])
    if "httpOnly" in cookie:
        out["httpOnly"] = bool(cookie["httpOnly"])

    return out


def load_cookie_json() -> List[Dict[str, Any]]:
    if not COOKIE_FILE.exists():
        raise FileNotFoundError(f"{COOKIE_FILE} does not exist")

    raw = json.loads(COOKIE_FILE.read_text(encoding="utf-8"))

    if isinstance(raw, dict) and isinstance(raw.get("cookies"), list):
        items = raw["cookies"]
    elif isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        # Also tolerate a simple {"cookie_name":"cookie_value"} mapping.
        items = [
            {"name": str(k), "value": str(v), "domain": f".{SITE_HOST}", "path": "/"}
            for k, v in raw.items()
            if not isinstance(v, (dict, list))
        ]
    else:
        raise ValueError("cookie.json must be a list, an object with 'cookies', or a name/value mapping")

    prepared: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            cooked = sanitize_cookie(item)
            if cooked:
                prepared.append(cooked)

    if not prepared:
        raise ValueError("cookie.json contains no usable cookies")

    return prepared


def visible_login(page: Page) -> bool:
    """
    Conservative logged-out heuristic.
    A visible login/sign-in control is treated as logged out.
    """
    selectors = [
        'a[href*="/login"]',
        'a[href*="/signin"]',
        'button:has-text("Log in")',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'a:has-text("Log in")',
        'a:has-text("Login")',
        'a:has-text("Sign in")',
    ]

    for selector in selectors:
        try:
            loc = page.locator(selector)
            count = min(loc.count(), 5)
            for i in range(count):
                if loc.nth(i).is_visible(timeout=400):
                    return True
        except Exception:
            continue

    try:
        body = page.locator("body").inner_text(timeout=1500)
        # Only inspect a modest amount of body text to reduce accidental matches.
        if body and LOGIN_RE.search(body[:20000]):
            return True
    except Exception:
        pass

    return False


def confirm_login(page: Page) -> bool:
    for attempt in range(3):
        if visible_login(page):
            if attempt < 2:
                time.sleep(1.5)
                continue
            return True
        return False
    return True


def wait_settled(page: Page, seconds: float = 3.0) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline and not STOP.is_set():
        try:
            page.wait_for_timeout(250)
        except Exception:
            time.sleep(0.25)


def establish_session(page: Page) -> bool:
    """
    Reuse the persistent profile first.
    Only inject cookie.json when the profile appears logged out.
    """
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)

    with STATE.lock:
        STATE.page = page
        STATE.browser_ready = True

    try:
        page.set_default_timeout(5_000)
        page.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)

        logging.info("Opening %s with persistent profile...", SITE_URL)
        page.goto(SITE_URL, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
        wait_settled(page, 2.5)

        if not confirm_login(page):
            log_session(True, "persistent-profile", "existing profile session accepted")
            return True

        logging.warning("Profile is logged out; loading %s", COOKIE_FILE)
        cookies = load_cookie_json()

        # Only replace cookies for this site's host. We intentionally keep other
        # profile state untouched so browser identity/storage remains persistent.
        try:
            page.context.clear_cookies()
        except Exception:
            pass

        page.context.add_cookies(cookies)
        logging.info("Injected %d cookies from cookie.json", len(cookies))

        page.goto(SITE_URL, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
        wait_settled(page, 3.0)

        if confirm_login(page):
            log_session(False, "cookie.json", "login controls are still visible after cookie injection")
            return False

        log_session(True, "cookie.json", "cookie session accepted and stored in persistent profile")
        return True

    except Exception as exc:
        log_session(False, "session-check", f"{type(exc).__name__}: {exc}")
        with STATE.lock:
            STATE.last_error = f"session initialization: {type(exc).__name__}: {exc}"
        return False


def capture_m3u8(page: Page, video_url: str) -> Dict[str, Any]:
    if not video_url.startswith(("http://", "https://")):
        return {"success": False, "error": "URL must start with http:// or https://"}

    parsed = urlparse(video_url)
    if parsed.netloc and SITE_HOST not in parsed.netloc.lower():
        return {
            "success": False,
            "error": f"URL host must be {SITE_HOST}",
        }

    found: set[str] = set()

    def on_request(request: Any) -> None:
        try:
            add_m3u8(found, request.url)
        except Exception:
            pass

    def on_response(response: Any) -> None:
        try:
            add_m3u8(found, response.url)
        except Exception:
            pass

    page.on("request", on_request)
    page.on("response", on_response)

    try:
        with STATE.lock:
            STATE.busy = True
            STATE.current_url = video_url
            STATE.last_job_at = time.time()
            STATE.last_error = ""

        logging.info("▶ Extracting: %s", video_url)
        page.goto(video_url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
        wait_settled(page, 2.0)

        # If the destination itself shows a login state, don't report an empty
        # manifest as if extraction simply failed.
        if confirm_login(page):
            log_session(False, "video-page-check", "video page shows login controls")
            return {
                "success": False,
                "error": "SESSION_EXPIRED",
                "loggedIn": False,
                "m3u8": [],
            }

        # Give player scripts/network requests time to create the media manifest.
        deadline = time.time() + EXTRACTION_SETTLE_SECONDS
        while time.time() < deadline and not STOP.is_set():
            try:
                html = page.content()
                for url in extract_m3u8_from_text(html):
                    found.add(url)

                # Capture video/source URLs exposed directly in the DOM.
                for selector in ("video", "source"):
                    try:
                        loc = page.locator(selector)
                        for i in range(min(loc.count(), 20)):
                            src = loc.nth(i).get_attribute("src")
                            if src:
                                add_m3u8(found, src)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(0.75)

        # One final page scan.
        try:
            html = page.content()
            for url in extract_m3u8_from_text(html):
                found.add(url)
        except Exception:
            pass

        manifests = sorted(found)
        result = {
            "success": bool(manifests),
            "loggedIn": True,
            "url": video_url,
            "m3u8": manifests,
            "count": len(manifests),
        }

        if manifests:
            logging.info("✅ Found %d .m3u8 URL(s)", len(manifests))
            for idx, manifest in enumerate(manifests, 1):
                logging.info("   [%d] %s", idx, manifest)
        else:
            logging.warning("⚠️ No .m3u8 URL observed for this video")

        return result

    except Exception as exc:
        logging.error("Extraction failed: %s: %s", type(exc).__name__, exc)
        return {
            "success": False,
            "loggedIn": STATE.logged_in,
            "url": video_url,
            "m3u8": sorted(found),
            "count": len(found),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        with STATE.lock:
            STATE.busy = False
        try:
            page.remove_listener("request", on_request)
            page.remove_listener("response", on_response)
        except Exception:
            pass

        # Return to the authenticated home page so the persistent browser is idle
        # and ready for the next API request.
        if not STOP.is_set():
            try:
                page.goto(SITE_URL, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                wait_settled(page, 1.5)
                if confirm_login(page):
                    log_session(False, "post-extraction-check", "login controls appeared after returning home")
                else:
                    log_session(True, "persistent-profile", "session still active after extraction")
            except Exception as exc:
                logging.warning("Could not return to home page: %s", exc)


def keepalive(page: Page) -> None:
    logging.info("⏱️ Keep-alive refresh")
    with STATE.lock:
        STATE.last_keepalive = time.time()

    try:
        page.goto(SITE_URL, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
        wait_settled(page, 2.0)

        if confirm_login(page):
            log_session(False, "keepalive-check", "login controls visible after keep-alive refresh")
        else:
            log_session(True, "persistent-profile", "session survived keep-alive refresh")

    except Exception as exc:
        logging.warning("Keep-alive refresh failed: %s: %s", type(exc).__name__, exc)
        with STATE.lock:
            STATE.last_error = f"keepalive: {type(exc).__name__}: {exc}"


def process_jobs(page: Page) -> None:
    last_activity = time.time()

    while not STOP.is_set():
        timeout = 1.0
        try:
            job = JOBS.get(timeout=timeout)
        except queue.Empty:
            if (
                not STATE.busy
                and time.time() - last_activity >= KEEPALIVE_SECONDS
            ):
                keepalive(page)
                last_activity = time.time()
            continue

        try:
            last_activity = time.time()

            if not STATE.logged_in:
                job.result = {
                    "success": False,
                    "error": "SESSION_EXPIRED",
                    "loggedIn": False,
                    "m3u8": [],
                }
            else:
                job.result = capture_m3u8(page, job.url)

            with STATE.lock:
                STATE.last_result = job.result
        except Exception as exc:
            job.result = {
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
                "loggedIn": STATE.logged_in,
            }
            with STATE.lock:
                STATE.last_error = job.result["error"]
                STATE.last_result = job.result
        finally:
            job.done.set()
            JOBS.task_done()


def api_json(handler: BaseHTTPRequestHandler, payload: Dict[str, Any], status: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class APIHandler(BaseHTTPRequestHandler):
    server_version = "FaphouseWorker/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        logging.info("API %s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        if self.path == "/status":
            api_json(self, {
                "success": True,
                "worker": STATE.snapshot(),
                "queueSize": JOBS.qsize(),
            })
            return

        if self.path == "/health":
            api_json(self, {
                "success": True,
                "ready": STATE.browser_ready and not STOP.is_set(),
                "loggedIn": STATE.logged_in,
                "busy": STATE.busy,
            })
            return

        api_json(self, {"success": False, "error": "not found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path != "/extract":
            api_json(self, {"success": False, "error": "not found"}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 64 * 1024:
                raise ValueError("invalid request body size")

            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
            url = str(data.get("url") or "").strip()

            if not url:
                raise ValueError("missing 'url'")

            if not url.startswith(("http://", "https://")):
                raise ValueError("url must start with http:// or https://")

            job = Job(url=url, done=threading.Event())

            try:
                JOBS.put_nowait(job)
            except queue.Full:
                api_json(self, {"success": False, "error": "worker queue is full"}, 503)
                return

            if not job.done.wait(REQUEST_TIMEOUT_SECONDS):
                api_json(self, {
                    "success": False,
                    "error": "worker timed out waiting for extraction",
                }, 504)
                return

            api_json(self, job.result or {
                "success": False,
                "error": "worker returned no result",
            })
        except json.JSONDecodeError:
            api_json(self, {"success": False, "error": "invalid JSON"}, 400)
        except ValueError as exc:
            api_json(self, {"success": False, "error": str(exc)}, 400)
        except Exception as exc:
            logging.exception("API error")
            api_json(self, {
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
            }, 500)


def start_api_server() -> ThreadingHTTPServer:
    global API_SERVER
    server = ThreadingHTTPServer((API_HOST, API_PORT), APIHandler)
    server.daemon_threads = True
    API_SERVER = server

    thread = threading.Thread(
        target=server.serve_forever,
        name="faphouse-api",
        daemon=True,
    )
    thread.start()

    logging.info("API listening on http://%s:%d", API_HOST, API_PORT)
    return server


def handle_signal(signum: int, _frame: Any) -> None:
    logging.info("Received signal %s — shutting down", signum)
    STOP.set()
    if API_SERVER is not None:
        try:
            API_SERVER.shutdown()
        except Exception:
            pass


def browser_action(page: Page) -> None:
    """
    Called by StealthyFetcher after the initial page exists.
    It owns all Playwright operations from here onward.
    """
    if not establish_session(page):
        logging.error("Worker started but session is DEAD.")
    else:
        logging.info(
            "✅ Persistent browser ready. Submit URLs through submit.py while this stays running."
        )

    process_jobs(page)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Persistent Faphouse M3U8 worker")
    parser.add_argument("--host", default=API_HOST, help="API bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=API_PORT, help="API port (default: 8787)")
    parser.add_argument(
        "--keepalive-minutes",
        type=float,
        default=10.0,
        help="idle keep-alive interval in minutes (default: 10)",
    )
    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=15.0,
        help="maximum time to watch the video page for manifests (default: 15)",
    )
    parser.add_argument(
        "--real-chrome",
        action="store_true",
        help="ask Scrapling to use the installed Google Chrome",
    )
    return parser.parse_args()


def main() -> int:
    global API_HOST, API_PORT, KEEPALIVE_SECONDS, EXTRACTION_SETTLE_SECONDS

    args = parse_args()
    API_HOST = args.host
    API_PORT = args.port
    KEEPALIVE_SECONDS = max(30.0, args.keepalive_minutes * 60.0)
    EXTRACTION_SETTLE_SECONDS = max(1.0, args.settle_seconds)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if StealthyFetcher is None:
        logging.error("Scrapling/Playwright import failed: %s", IMPORT_ERROR)
        return 1

    PROFILE_DIR.mkdir(parents=True, exist_ok=True)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    start_api_server()

    logging.info("Profile : %s", PROFILE_DIR)
    logging.info("Cookies : %s", COOKIE_FILE)
    logging.info("Headless: yes")

    try:
        StealthyFetcher.fetch(
            SITE_URL,
            headless=True,
            solve_cloudflare=True,
            hide_canvas=True,
            block_webrtc=False,
            real_chrome=args.real_chrome,
            user_data_dir=str(PROFILE_DIR),
            page_action=browser_action,
        )
    except Exception as exc:
        if not STOP.is_set():
            logging.exception("Browser worker exited: %s", exc)
            return 1
    finally:
        STOP.set()
        if API_SERVER is not None:
            try:
                API_SERVER.server_close()
            except Exception:
                pass

    logging.info("Worker stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
