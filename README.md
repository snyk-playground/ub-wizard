# Universal Broker UI

A small [Streamlit](https://streamlit.io/) app that walks through **Snyk Universal Broker** setup: session initialization against the Snyk REST API, tenant selection, connections, credentials, org integration, and a generated `docker run` command. The HTTP client lives in `ub_client.py` (`UniversalBrokerClient`).

## Prerequisites

- **Python 3.10+** (3.10 is what this repo was developed with)
- A **Snyk personal API token** with access to Universal Broker (the in-app help notes that service accounts are not supported for app install)
- Network access to your chosen Snyk API region (see [Snyk regional hosting](https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency))

## Quick start (local)

1. **Clone** (after you create the GitHub repo and push, or clone your existing remote):

   ```bash
   git clone <your-repo-url>
   cd ub_gui
   ```

2. **Create and activate a virtual environment**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the app**

   ```bash
   streamlit run app.py
   ```

5. Open the URL Streamlit prints (usually [http://localhost:8501](http://localhost:8501)).

## First-time use in the browser

1. Expand **Start / Resume**.
2. Choose **Snyk region** or a **custom REST API base URL** (and broker server URL if custom).
3. Paste your **API token**, optionally set **SSL** options, then click **Initialize session**.
4. If you did not enter a **Tenant ID**, pick a tenant from the list when it appears.
5. Use the rest of the wizard for installs, deployments, connections, credentials, and **Generate Docker Command** as needed.

Optional fields (install ID, deployment ID, connection ID, client ID/secret) are for resuming an existing setup.

## Putting this on GitHub

1. Create a new empty repository on GitHub (no README/license there if you want this repo’s `README.md` to be the source of truth).
2. In your project folder:

   ```bash
   git init
   git add app.py ub_client.py requirements.txt README.md
   git commit -m "Initial commit: Universal Broker Streamlit UI"
   git branch -M main
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```

3. **Do not commit** virtualenvs, secrets, or API tokens. Keep `.venv/` out of git (see below).

### Recommended `.gitignore`

Create a `.gitignore` in the repo root so you do not push secrets or local junk:

```gitignore
.venv/
__pycache__/
*.py[cod]
.env
.env.*
.streamlit/secrets.toml
.DS_Store
```

## Project layout

| File | Role |
|------|------|
| `app.py` | Streamlit UI and forms |
| `ub_client.py` | REST client for Snyk Universal Broker (`/rest` paths, JSON:API headers) |
| `requirements.txt` | Pinned Python dependencies |

## Optional: faster reloads

Streamlit may suggest installing [watchdog](https://pypi.org/project/watchdog/) for quicker file watching during development:

```bash
pip install watchdog
```

## License

Add a `LICENSE` file in the repository if you want an explicit open-source or proprietary terms.
