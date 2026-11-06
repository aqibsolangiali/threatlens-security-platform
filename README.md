# ThreatLens 🔎

**An explainable URL safety desk with an optional, limited HTML text inspection and a Chrome extension.** ThreatLens checks URL patterns, can fetch a small amount of public page HTML when you select the inspection option, and shows the signals behind its score.

> **Important:** ThreatLens is an educational security project, not antivirus software or a reputation service. Its score does not prove that a site is safe or malicious. Optional page inspection requests limited HTML text without running scripts, submitting forms, following page-level refreshes, or downloading linked files. Do not paste private, password-reset, or one-time login links into the scanner.

## What it does

- Analyzes a URL and returns a 0–100 risk indicator with plain-language findings.
- When selected in the dashboard, retrieves up to 500 KB of public HTML and displays the page title, description, and a short visible-text preview.
- Checks a few page signals, including password fields, cross-domain form actions, urgent credential requests, and executable download links.
- When selected in the dashboard and configured by the site owner, checks the submitted URL against Google's Safe Browsing v5 threat lists.
- Blocks non-public IP destinations, pins the validated IP for the connection, follows at most two redirects, and only allows standard HTTP/HTTPS ports during page inspection.
- Looks for patterns such as HTTP, raw IP addresses, encoded internationalized domains, unusually deep subdomains, `@` user-info tricks, very long URLs, multiple hyphens, sensitive wording in a domain, and uncommon ports.
- Saves the scanned domain (not the full path or query string) and summary counts in SQLite history.
- Includes an optional Chrome extension to check the current tab through the local API.
- Provides a responsive dashboard, REST API, Dockerfile, and interactive API docs.

## Screenshots

Add screenshots of the dashboard and extension here after running the app, for example:

```md
![ThreatLens dashboard](docs/dashboard.png)
![ThreatLens extension](docs/extension.png)
```

## Run locally

Requires Python 3.10 or newer.

```bash
cd threatlens
python -m venv .venv
```

Activate the environment:

- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

Then install and start the server:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. Interactive API documentation is at <http://127.0.0.1:8000/docs>.

## API examples

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"http://secure-account-verify.example-login.com/signin","inspect_page":false}'
```

To request limited page inspection from the API, set `inspect_page` to `true`. The dashboard includes a checkbox for this. The optional Google lookup uses `check_reputation: true` and requires the `GOOGLE_SAFE_BROWSING_API_KEY` environment variable. The browser extension remains URL-only unless its request is changed.

Other endpoints:

- `GET /api/health` — service status
- `GET /api/stats` — scan totals and risk counts
- `GET /api/history?limit=20` — recent scans
- `DELETE /api/history` — clear local history

## Install the Chrome extension

1. Start ThreatLens locally at `http://127.0.0.1:8000`.
2. In Chrome, open `chrome://extensions` and enable **Developer mode**.
3. Choose **Load unpacked** and select the `extension` folder.
4. Open an HTTP or HTTPS page, select the ThreatLens extension, and analyze the current tab.

The extension only has `activeTab` permission and sends the current URL to the local ThreatLens server when you click **Analyze this link**. It does not read page contents or automatically block navigation.

## Docker

From the project directory:

```bash
docker build -t threatlens .
docker run --rm -p 8000:8000 -v "$(pwd)/data:/data" threatlens
```

The SQLite file is stored in the mounted `data` directory so scan history persists between container runs.

## How the score works

ThreatLens adds small, documented points for each suspicious URL pattern and caps the result at 100. The dashboard groups scores into three bands: 0–24 (fewer signals), 25–49 (use caution), and 50–100 (higher concern). This transparent heuristic is intentionally simple: attackers change tactics, and harmless sites can also match a warning pattern.

## Security and privacy notes

- URL-pattern checks are local; optional page inspection makes an outbound request from the server to the entered public website.
- The optional Google Safe Browsing check sends the full URL to Google and is only made after the visitor selects its checkbox. Google's Safe Browsing API is for non-commercial use; commercial projects should use an appropriate commercial service. Its list can miss risky sites or flag safe ones. Set `GOOGLE_SAFE_BROWSING_API_KEY` as a secret environment variable in Render; never commit the key to GitHub. A Google match warning is phrased as a possible risk and attributed to Google with its advisory link. See [Google Safe Browsing's usage guidance](https://developers.google.com/safe-browsing/reference/Appropriate.Usage).
- Page inspection rejects non-public destinations, pins the resolved IP, caps redirects, timeout, and response size, and reads HTML text only. This is a useful risk-reduction measure, not a guarantee against every network attack.
- Scan history stores only the domain, score, and findings in `threatlens.db`; it does not retain the full URL path/query or inspected page preview. The inspection request still sends the entered public URL from the server to that site. Do not paste private, password-reset, or one-time login links into the scanner.
- Do not paste private, password-reset, or one-time login links into any scanner, including this project. URLs may contain secrets.
- A URL can look normal and still lead to harmful content. Verify important links through a trusted source.

## Roadmap

- Add optional, clearly disclosed threat-intelligence providers behind a user-controlled setting.
- Add domain normalization and lookalike-domain education.
- Add export and retention controls for local history.
- Add accessibility review and automated API checks.

## License

MIT. See [LICENSE](LICENSE).
