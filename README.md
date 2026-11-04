# ThreatLens 🔎

**An explainable URL safety desk with a local-first dashboard and an optional Chrome extension.** ThreatLens checks for common suspicious URL patterns, shows the signals behind its score, and keeps a private scan history on your machine.

> **Important:** ThreatLens is an educational security project, not antivirus software or a reputation service. It does not prove that a site is safe or malicious. It analyzes the URL text only and never opens or downloads the target website.

## What it does

- Analyzes a URL and returns a 0–100 risk indicator with plain-language findings.
- Looks for patterns such as HTTP, raw IP addresses, encoded internationalized domains, unusually deep subdomains, `@` user-info tricks, very long URLs, multiple hyphens, sensitive wording in a domain, and uncommon ports.
- Saves scan history and summary counts in a local SQLite database.
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
  -d '{"url":"http://secure-account-verify.example-login.com/signin"}'
```

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

- URL checks are deterministic and local; the project does not call external threat-intelligence providers.
- Scans are stored in `threatlens.db` on the machine running the server. Do not expose the development server publicly with real user data.
- Do not paste private, password-reset, or one-time login links into any scanner, including this project. URLs may contain secrets.
- A URL can look normal and still lead to harmful content. Verify important links through a trusted source.

## Roadmap

- Add optional, clearly disclosed threat-intelligence providers behind a user-controlled setting.
- Add domain normalization and lookalike-domain education.
- Add export and retention controls for local history.
- Add accessibility review and automated API checks.

## License

MIT. See [LICENSE](LICENSE).
