from __future__ import annotations

import codecs
import http.client
import ipaddress
import json
import os
import re
import socket
import sqlite3
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("THREATLENS_DB_PATH", Path(__file__).resolve().parent.parent / "threatlens.db"))
app = FastAPI(title="ThreatLens", version="1.2.0", description="Explainable URL and limited page-text safety analysis")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

MAX_PAGE_BYTES = 512_000
FETCH_TIMEOUT_SECONDS = 4
MAX_REDIRECTS = 2


class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    inspect_page: bool = False
    check_reputation: bool = False


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            findings TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")


init_db()


def risk_band(score: int) -> tuple[str, str]:
    if score >= 50:
        return "high", "High risk indicators"
    if score >= 25:
        return "medium", "Caution advised"
    return "low", "Fewer risk indicators"


def analyze_url(raw: str) -> dict:
    value = raw.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Enter a website address to scan.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=422, detail="Enter a valid HTTP or HTTPS website address.")
    try:
        port = parsed.port
    except ValueError:
        raise HTTPException(status_code=422, detail="The website address has an invalid port.")
    if parsed.username or parsed.password:
        # Retain detection of @-style deceptive addresses while never fetching credentials.
        pass
    host = parsed.hostname.lower().rstrip(".")
    findings: list[dict] = []
    score = 0

    def flag(points: int, title: str, detail: str, severity: str = "warning") -> None:
        nonlocal score
        score += points
        findings.append({"title": title, "detail": detail, "severity": severity})

    if parsed.scheme == "http":
        flag(18, "Connection is not encrypted", "This address uses HTTP, so information sent to the site may not be protected in transit.")
    else:
        findings.append({"title": "HTTPS connection", "detail": "The address uses HTTPS. This protects the connection, but does not prove the site itself is trustworthy.", "severity": "good"})

    try:
        ipaddress.ip_address(host)
        flag(20, "Uses a raw IP address", "Legitimate sites can use IP addresses, but unexpected numeric addresses are often used in deceptive links.")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        flag(22, "Internationalized domain", "This domain uses encoded characters. Some lookalike domains use characters that resemble familiar letters.")
    if host.count(".") >= 4:
        flag(10, "Unusually deep subdomain", "The address contains several subdomain levels. Check the registered domain carefully.")
    if "@" in parsed.netloc:
        flag(25, "Misleading @ symbol", "Text before @ in a URL can disguise the destination. The browser connects to the host after @.")
    if len(value) > 100:
        flag(8, "Unusually long address", "Long URLs can hide the real destination or contain confusing tracking parameters.")
    if host.count("-") >= 3:
        flag(8, "Many hyphens in domain", "A domain with several hyphens deserves a closer look, especially if it imitates a known brand.")
    if re.search(r"(login|verify|secure|account|update|password|wallet|bank)", host):
        flag(12, "Sensitive wording in domain", "The domain contains wording often used in account or payment lures. Confirm you recognize the exact domain.")
    if port and port not in {80, 443}:
        flag(10, "Non-standard web port", f"This site uses port {port}, which is less common for public websites.")
    if not findings or all(f["severity"] == "good" for f in findings):
        findings.append({"title": "No obvious URL patterns found", "detail": "This basic check did not identify common suspicious URL patterns. It cannot verify the site's content or reputation.", "severity": "good"})

    score = min(score, 100)
    level, label = risk_band(score)
    return {"url": value, "domain": host, "score": score, "level": level, "label": label, "findings": findings}


class VisiblePageParser(HTMLParser):
    """Extract a small amount of visible text and behavior signals; never execute page code."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self.text_parts: list[str] = []
        self.in_title = False
        self.hidden_depth = 0
        self.password_fields = 0
        self.form_actions: list[str] = []
        self.download_links = 0
        self.iframes = 0
        self.meta_refresh = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "title":
            self.in_title = True
        if tag in {"script", "style", "noscript", "svg"}:
            self.hidden_depth += 1
        if tag == "meta":
            if values.get("name", "").lower() == "description":
                self.description = values.get("content", "")
            if values.get("http-equiv", "").lower() == "refresh":
                self.meta_refresh = True
        if tag == "input" and values.get("type", "").lower() == "password":
            self.password_fields += 1
        if tag == "form":
            self.form_actions.append(values.get("action", ""))
        if tag == "iframe":
            self.iframes += 1
        if tag == "a" and re.search(r"\.(exe|msi|apk|bat|cmd|scr|js)(?:$|[?#])", values.get("href", ""), re.I):
            self.download_links += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        if tag in {"script", "style", "noscript", "svg"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        if self.in_title:
            self.title = (self.title + " " + cleaned).strip()[:200]
        if self.hidden_depth == 0 and sum(map(len, self.text_parts)) < 12_000:
            self.text_parts.append(cleaned)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a previously validated public IP while preserving the requested Host header."""

    def __init__(self, host: str, port: int, pinned_ip: str) -> None:
        super().__init__(host, port=port, timeout=FETCH_TIMEOUT_SECONDS)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str) -> None:
        super().__init__(host, port=port, timeout=FETCH_TIMEOUT_SECONDS)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def validated_public_ip(host: str, port: int) -> str:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        ascii_host = host.encode("idna").decode("ascii")
        addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(ascii_host, port, type=socket.SOCK_STREAM)]
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("This address does not resolve only to public internet addresses, so it was not opened.")
    return str(addresses[0])


def fetch_html(raw_url: str) -> tuple[str, str, bytes] | tuple[None, str, None]:
    current = raw_url
    for redirect_count in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None, "The page address is not a supported public HTTP or HTTPS URL.", None
        host = parsed.hostname.rstrip(".")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return None, "The page address has an invalid port, so inspection was skipped.", None
        if port not in {80, 443} or (parsed.scheme == "https" and port != 443) or (parsed.scheme == "http" and port != 80):
            return None, "The page uses a non-standard port, so page inspection was skipped.", None
        try:
            pinned_ip = validated_public_ip(host, port)
        except (OSError, UnicodeError, ValueError, socket.gaierror) as exc:
            return None, str(exc) if isinstance(exc, ValueError) else "The public site could not be resolved, so page inspection was skipped.", None

        conn: http.client.HTTPConnection
        request_host = host.encode("idna").decode("ascii")
        if parsed.scheme == "https":
            conn = PinnedHTTPSConnection(request_host, port, pinned_ip)
        else:
            conn = PinnedHTTPConnection(request_host, port, pinned_ip)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        path = quote(path, safe="/%:@!$&'()*+,;=-._~?#")
        try:
            conn.request("GET", path, headers={
                "User-Agent": "ThreatLens-SafeInspector/1.1 (+URL text and limited HTML inspection)",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = conn.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                conn.close()
                if not location:
                    return None, "The site returned a redirect without a destination.", None
                if redirect_count >= MAX_REDIRECTS:
                    return None, "The site redirected too many times; inspection stopped.", None
                current = urljoin(current, location)
                continue
            content_type = response.getheader("Content-Type", "").lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                conn.close()
                return None, f"The site returned {content_type.split(';', 1)[0] or 'non-HTML content'}; only HTML text is inspected.", None
            declared_size = response.getheader("Content-Length")
            if declared_size and declared_size.isdigit() and int(declared_size) > MAX_PAGE_BYTES:
                conn.close()
                return None, "The page is larger than the inspection limit; no page text was read.", None
            body = response.read(MAX_PAGE_BYTES + 1)
            conn.close()
            if len(body) > MAX_PAGE_BYTES:
                body = body[:MAX_PAGE_BYTES]
                note = "The page was truncated at the inspection size limit."
            else:
                note = ""
            charset_match = re.search(r"charset\s*=\s*['\"]?([\w.-]+)", content_type)
            charset = charset_match.group(1) if charset_match else "utf-8"
            try:
                codecs.lookup(charset)
            except LookupError:
                charset = "utf-8"
            return current, note, body.decode(charset, errors="replace").encode("utf-8")
        except (OSError, http.client.HTTPException, UnicodeError, TimeoutError):
            conn.close()
            return None, "The page could not be retrieved within the safe inspection limits.", None
    return None, "The page could not be inspected.", None


def inspect_page(raw_url: str, url_domain: str) -> dict:
    final_url, note, encoded_html = fetch_html(raw_url)
    if encoded_html is None:
        return {"status": "not_inspected", "message": note, "title": "", "description": "", "excerpt": "", "findings": [], "points": 0}

    parser = VisiblePageParser()
    try:
        parser.feed(encoded_html.decode("utf-8", errors="replace"))
        parser.close()
    except Exception:
        return {"status": "not_inspected", "message": "The page text could not be safely parsed.", "title": "", "description": "", "excerpt": "", "findings": [], "points": 0}

    final_host = (urlparse(final_url).hostname or "").lower().rstrip(".")
    visible_text = " ".join(parser.text_parts)
    findings: list[dict] = []
    points = 0

    def flag(amount: int, title: str, detail: str) -> None:
        nonlocal points
        points += amount
        findings.append({"title": title, "detail": detail, "severity": "warning"})

    if parser.password_fields:
        flag(8, "Page contains a password field", "This can be normal on sign-in pages, but only enter a password on a site whose exact address you trust.")
    for action in parser.form_actions:
        if action:
            action_url = urljoin(final_url, action)
            action_host = (urlparse(action_url).hostname or "").lower().rstrip(".")
            if action_host and action_host != final_host:
                flag(18, "Form sends data to another domain", "A page form points to a different domain. Check carefully before submitting any information.")
                break
    if parser.meta_refresh:
        flag(8, "Automatic page redirect found", "The page contains a browser-level refresh redirect. The destination was not followed by this inspector.")
    if parser.iframes:
        flag(5, "Embedded frame found", "The page embeds other content. This is common, but the embedded content may have a different owner.")
    if parser.download_links:
        flag(8, "Executable or script download link found", "The page links to a file type that can run code. ThreatLens did not download or open it.")
    if re.search(r"(?:account\s+(?:is\s+)?suspended|verify\s+(?:your\s+)?identity|urgent\s+action|required immediately|enter\s+your\s+(?:password|recovery phrase)|claim\s+(?:your\s+)?prize)", visible_text, re.I):
        flag(14, "Urgent or credential-seeking wording", "The visible page text contains wording often used to pressure visitors or request sensitive information. Review the page carefully.")

    if not findings:
        findings.append({"title": "No listed page warning found", "detail": "The limited HTML check did not find the specific page patterns ThreatLens looks for. This is not proof the page is safe.", "severity": "good"})

    excerpt = visible_text[:900].strip()
    if len(visible_text) > 900:
        excerpt += "…"
    description = " ".join(parser.description.split())[:400]
    return {
        "status": "inspected",
        "message": note or "Read limited HTML text only. Scripts were not run, forms were not submitted, and files were not downloaded.",
        "final_url": final_url if final_url != raw_url else "",
        "title": parser.title,
        "description": description,
        "excerpt": excerpt,
        "findings": findings,
        "points": points,
        "final_domain": final_host if final_host != url_domain else "",
    }


def google_safe_browsing_lookup(urls: list[str]) -> dict:
    """Optional non-commercial reputation check; raw URLs are sent only after user opt-in."""
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "message": "Google Safe Browsing is not connected. Add GOOGLE_SAFE_BROWSING_API_KEY in Render to enable this check.",
            "matches": [],
        }

    query = urlencode([("key", api_key), *[("urls", item) for item in urls]])
    endpoint = "https://safebrowsing.googleapis.com/v5/urls:search?" + query
    request = Request(endpoint, headers={"Accept": "application/json", "User-Agent": "ThreatLens/1.2"})
    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read(256_000).decode("utf-8"))
    except HTTPError as exc:
        # Record only the HTTP status. Never log the request URL (it contains the key)
        # or return Google's raw response body to the visitor.
        status_messages = {
            400: "Google rejected the lookup request (HTTP 400).",
            401: "Google did not accept the API key (HTTP 401).",
            403: "Google denied API access (HTTP 403). Check that Safe Browsing API is enabled for the key's project and that the key's API restriction allows it.",
            429: "Google rate-limited the lookup or the project reached its quota (HTTP 429).",
        }
        message = status_messages.get(exc.code, f"Google returned an error (HTTP {exc.code}).")
        print(f"ThreatLens Safe Browsing lookup failed: HTTP {exc.code}")
        return {
            "status": "unavailable",
            "message": f"{message} URL-pattern and page-text checks are still shown.",
            "matches": [],
        }
    except (URLError, TimeoutError, OSError):
        print("ThreatLens Safe Browsing lookup failed: network error or timeout")
        return {
            "status": "unavailable",
            "message": "ThreatLens could not reach Google Safe Browsing (network error or timeout). URL-pattern and page-text checks are still shown.",
            "matches": [],
        }
    except ValueError:
        print("ThreatLens Safe Browsing lookup failed: invalid JSON response")
        return {
            "status": "unavailable",
            "message": "Google returned a response ThreatLens could not read. URL-pattern and page-text checks are still shown.",
            "matches": [],
        }

    matches = payload.get("threats", []) if isinstance(payload, dict) else []
    if matches:
        types = sorted({str(item) for match in matches if isinstance(match, dict) for item in (match.get("threatTypes") or match.get("threat_types") or [])})
        readable = ", ".join(types) if types else "a known unsafe-site list"
        return {
            "status": "match",
            "message": f"Google Safe Browsing reports a match for {readable}. Treat this address as potentially unsafe.",
            "matches": types,
            "attribution": "Advisory provided by Google",
            "advisory_url": "https://developers.google.com/safe-browsing/v4/advisory",
        }
    return {
        "status": "no_match",
        "message": "No match was found in the Google Safe Browsing lists checked. This does not prove the website is safe.",
        "matches": [],
    }


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ThreatLens", "version": "1.2.0"}


@app.post("/api/scan")
def scan(request: ScanRequest):
    result = analyze_url(request.url)
    page = None
    if request.inspect_page:
        page = inspect_page(result["url"], result["domain"])
        result["page_inspection"] = page
        result["findings"].extend(page["findings"])
        result["score"] = min(100, result["score"] + page["points"])
    if request.check_reputation:
        lookup_urls = [result["url"]]
        if page and page.get("status") == "inspected" and page.get("final_url"):
            final_url = page.get("final_url")
            if final_url and final_url not in lookup_urls:
                lookup_urls.append(final_url)
        reputation = google_safe_browsing_lookup(lookup_urls)
        result["reputation"] = reputation
        if reputation["status"] == "match":
            result["score"] = max(result["score"], 70)
            result["findings"].append({
                "title": "Google Safe Browsing match",
                "detail": reputation["message"],
                "severity": "warning",
            })
    result["score"] = min(result["score"], 100)
    result["level"], result["label"] = risk_band(result["score"])
    created = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO scans (url, domain, score, level, findings, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            # History is shared by all visitors on a public deployment; keep only the domain.
            (result["domain"], result["domain"], result["score"], result["level"], json.dumps(result["findings"]), created),
        )
        result["id"] = cursor.lastrowid
        result["created_at"] = created
    return result


@app.get("/api/history")
def history(limit: int = 20):
    limit = max(1, min(limit, 100))
    with db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "domain": r["domain"], "score": r["score"], "level": r["level"], "created_at": r["created_at"]} for r in rows]


@app.get("/api/stats")
def stats():
    with db() as conn:
        row = conn.execute("SELECT COUNT(*) total, SUM(CASE WHEN level='high' THEN 1 ELSE 0 END) high, SUM(CASE WHEN level='medium' THEN 1 ELSE 0 END) medium FROM scans").fetchone()
    return {"total_scans": row["total"] or 0, "high_risk": row["high"] or 0, "caution": row["medium"] or 0}


@app.delete("/api/history")
def clear_history():
    with db() as conn:
        conn.execute("DELETE FROM scans")
    return {"deleted": True}
