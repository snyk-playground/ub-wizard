![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/main/oss-example.jpg)

# Universal Broker UI

A small [Streamlit](https://streamlit.io/) app that walks through **Snyk Universal Broker** setup: session initialization against the Snyk REST API, tenant selection, connections, credentials, org integration, and a generated `docker run` command. The HTTP client lives in `ub_client.py` (`UniversalBrokerClient`).

## Prerequisites

- **Python 3.10+** (3.10 is what this repo was developed with)
- A **Snyk personal API token** with access to Universal Broker (the in-app help notes that service accounts are not supported for app install)
- Network access to your chosen Snyk API region (see [Snyk regional hosting](https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency))

## Quick start (local)

1. **Clone** (after you create the GitHub repo and push, or clone your existing remote):

   ```bash
   git clone https://github.com/joeshope/ub-wizard
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
