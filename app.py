import os
import json
import streamlit as st
from typing import Any, Dict, List, Optional, Tuple

from ub_client import UniversalBrokerClient


def _credential_id_from_create_response(created: Any) -> Optional[str]:
	"""Parse credential id from POST /credentials response (JSON:API variants)."""
	if isinstance(created, list) and created:
		first = created[0]
		if isinstance(first, dict):
			return first.get("data", {}).get("id") or first.get("id")
	if not isinstance(created, dict):
		return None
	data = created.get("data")
	if isinstance(data, list) and data:
		item = data[0]
		return item.get("id") if isinstance(item, dict) else None
	if isinstance(data, dict):
		return data.get("id")
	return created.get("id")


def _sanitize_label(text: str) -> str:
	# Replace Unicode line/paragraph separators and other non-encodable chars with safe spaces
	if not isinstance(text, str):
		return str(text)
	return (
		text.replace("\u2028", " ")
		.replace("\u2029", " ")
		.replace("\r", " ")
		.replace("\n", " ")
	)


def _get_connection_config_fields(connection_type: str) -> Dict[str, Any]:
	"""Return the required fields for each connection type based on the API schema."""
	configs = {
		# Source Control Management
		"azure-repos": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://api.snyk.io", "help": "For Container Registry connections, use https://<broker.client.hostname>:<port>"},
			"azure_repos_host": {"type": "text", "label": "Azure Repos Host", "required": True, "placeholder": "My-azure-host.com"},
			"azure_repos_org": {"type": "text", "label": "Azure Repos Org", "required": True, "placeholder": "My-Org"},
			"azure_repos_token": {"type": "text", "label": "Azure Repos Token Reference Name", "required": True, "placeholder": "AZURE_REPOS_TOKEN"},
		},
		"bitbucket-server": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://api.snyk.io", "help": "For Container Registry connections, use https://<broker.client.hostname>:<port>"},
			"bitbucket": {"type": "text", "label": "Bitbucket Host", "required": True, "placeholder": "bitbucket.yourdomain.com"},
			"auth_type": {"type": "select", "label": "Authentication Type", "required": True, "options": ["PAT", "Username/Password"], "default": "PAT"},
			"bitbucket_username": {"type": "text", "label": "Bitbucket Username", "required": False, "placeholder": "<username>", "conditional": "Username/Password"},
			"bitbucket_password": {"type": "text", "label": "Bitbucket Password Reference Name", "required": False, "placeholder": "BITBUCKET_PASSWORD", "conditional": "Username/Password"},
			"bitbucket_pat": {"type": "text", "label": "Bitbucket PAT Reference Name", "required": False, "placeholder": "BITBUCKET_PAT", "conditional": "PAT"},
		},
		"github": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "http://your.broker.hostname:8000", "help": "Public URL of this broker client (scheme + host + port), e.g. http://broker.internal.company:8000"},
			"github_token": {"type": "text", "label": "GitHub token credential reference UUID", "required": True, "placeholder": "paste credential reference UUID from API"},
		},
		"github-enterprise": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://api.snyk.io", "help": "For Container Registry connections, use https://<broker.client.hostname>:<port>"},
			"github": {"type": "text", "label": "GitHub Enterprise Host", "required": True, "placeholder": "ghe.yourdomain.com"},
			"github_token": {"type": "text", "label": "GitHub Token Reference Name", "required": True, "placeholder": "GITHUB_TOKEN"},
		},
		"github-server-app": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://api.snyk.io", "help": "For Container Registry connections, use https://<broker.client.hostname>:<port>"},
			"github": {"type": "text", "label": "GitHub Host", "required": True, "placeholder": "ghe.yourdomain.com"},
			"github_api": {"type": "text", "label": "GitHub API", "required": True, "placeholder": "api.ghe.yourdomain.com"},
			"github_app_client_id": {"type": "text", "label": "GitHub App Client ID", "required": True, "placeholder": "<app-client-id>"},
			"github_app_id": {"type": "text", "label": "GitHub App ID", "required": True, "placeholder": "<app-id>"},
			"github_app_installation_id": {"type": "text", "label": "GitHub App Installation ID", "required": True, "placeholder": "<app-installation-id>"},
			"github_app_private_pem_path": {"type": "text", "label": "GitHub App Private PEM Path", "required": True, "placeholder": "<path-to-private-pem-file>"},
		},
		"github-cloud-app": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://api.snyk.io", "help": "For Container Registry connections, use https://<broker.client.hostname>:<port>"},
			"github": {"type": "text", "label": "GitHub Host", "required": True, "placeholder": "ghe.yourdomain.com"},
			"github_api": {"type": "text", "label": "GitHub API", "required": True, "placeholder": "api.ghe.yourdomain.com"},
			"github_app_client_id": {"type": "text", "label": "GitHub App Client ID", "required": True, "placeholder": "<app-client-id>"},
			"github_app_id": {"type": "text", "label": "GitHub App ID", "required": True, "placeholder": "<app-id>"},
			"github_app_installation_id": {"type": "text", "label": "GitHub App Installation ID", "required": True, "placeholder": "<app-installation-id>"},
			"github_app_private_pem_path": {"type": "text", "label": "GitHub App Private PEM Path", "required": True, "placeholder": "<path-to-private-pem-file>"},
		},
		"gitlab": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://api.snyk.io", "help": "For Container Registry connections, use https://<broker.client.hostname>:<port>"},
			"gitlab": {"type": "text", "label": "GitLab Host", "required": True, "placeholder": "gitlab.yourdomain.com"},
			"gitlab_token": {"type": "text", "label": "GitLab Token Reference Name", "required": True, "placeholder": "GITLAB_TOKEN"},
		},
		# Issue Tracking
		"jira": {
			"jira_hostname": {"type": "text", "label": "Jira Hostname", "required": True, "placeholder": "jira.yourdomain.com"},
			"auth_type": {"type": "select", "label": "Authentication Type", "required": True, "options": ["PAT", "Username/Password"], "default": "PAT"},
			"jira_username": {"type": "text", "label": "Jira Username", "required": False, "placeholder": "<jira-username>", "conditional": "Username/Password"},
			"jira_password": {"type": "text", "label": "Jira Password Reference Name", "required": False, "placeholder": "JIRA_PASSWORD", "conditional": "Username/Password"},
			"jira_pat": {"type": "text", "label": "Jira PAT Reference Name", "required": False, "placeholder": "JIRA_PAT", "conditional": "PAT"},
		},
		# Artifact Repositories
		"artifactory": {
			"artifactory_url": {"type": "text", "label": "Artifactory URL", "required": True},
		},
		"nexus": {
			"base_nexus_url": {"type": "text", "label": "Base Nexus URL", "required": True},
		},
		# Container Registries
		"acr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"artifactory-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"digitalocean-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_token": {"type": "text", "label": "CR Token Reference Name", "required": True, "placeholder": "CR_TOKEN"},
		},
		"docker-hub": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"ecr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_external_id": {"type": "text", "label": "CR External ID", "required": True},
			"cr_region": {"type": "text", "label": "CR Region", "required": True},
			"cr_role_arn": {"type": "text", "label": "CR Role ARN", "required": True},
		},
		"gcr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"github-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"gitlab-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"google-artifact-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"harbor-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"nexus-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
		"quay-cr": {
			"broker_client_url": {"type": "text", "label": "Broker Client URL", "required": True, "placeholder": "https://<broker.client.hostname>:<port>"},
			"cr_agent_url": {"type": "text", "label": "CR Agent URL", "required": True, "placeholder": "https://<agent-host>:<agent-port>"},
			"cr_base": {"type": "text", "label": "CR Base", "required": True, "placeholder": "cr.host.com"},
			"cr_password": {"type": "text", "label": "CR Password Reference Name", "required": True, "placeholder": "CR_PASSWORD"},
			"cr_username": {"type": "text", "label": "CR Username", "required": True},
		},
	}
	return configs.get(connection_type, {})

st.set_page_config(page_title="Universal Broker UI", page_icon="🧩", layout="centered")

if "state" not in st.session_state:
	st.session_state.state = {}

st.title("Universal Broker Setup Wizard")

with st.expander("Start / Resume", expanded=True):
	presets = UniversalBrokerClient.snyk_region_presets()
	region_mode = st.radio("API endpoint", ("Snyk region (recommended)", "Custom REST API base URL"), horizontal=True)
	if region_mode == "Snyk region (recommended)":
		region_choice = st.selectbox("Snyk region", options=list(presets.keys()), help="Matches SNYK-US-01, SNYK-US-02, etc. See regional hosting docs.")
		region_url, broker_server_url = presets[region_choice]
		st.caption(f"REST API: `{region_url}` · Broker server (for docker): `{broker_server_url}`")
	else:
		region_url = st.text_input("REST API base URL", placeholder="https://api.snyk.io", help="Must be the /rest host only, e.g. https://api.eu.snyk.io")
		broker_server_url = st.text_input(
			"Broker server URL (for docker)",
			placeholder="https://broker.eu.snyk.io",
			help="Required for custom API URL so the generated docker command sets BROKER_SERVER_URL. See Broker server URLs in Snyk docs.",
		)

	api_token = st.text_input("API Token", type="password", help="Personal Snyk API token (service accounts are not supported for Universal Broker app install).")

	st.markdown("**Tenant**")
	st.caption("Pick a tenant from your account, or enter a Tenant ID manually (e.g. when resuming).")
	tenant_manual = st.text_input("Tenant ID (optional if you select below)", placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")

	# SSL Configuration
	st.markdown("**SSL Configuration:**")
	verify_ssl = st.checkbox("Verify SSL certificates", value=True, help="Uncheck if you're getting certificate errors")
	ssl_cert_path = st.text_input("Custom SSL Certificate Path (optional)", placeholder="/path/to/certificate.pem", help="Path to a custom SSL certificate file if needed")

	st.markdown("**Resume:** supply these if you are continuing an existing Universal Broker setup.")
	install_id = st.text_input("Install ID (optional)")
	deployment_id = st.text_input("Deployment ID (optional)")
	connection_id_resume = st.text_input("Connection ID (optional)")
	client_id = st.text_input("Client ID (optional)")
	client_secret = st.text_input("Client Secret (optional)", type="password")

	submit = st.button("Initialize session")
	if submit:
		if not region_url or not api_token:
			st.error("REST API base URL and API Token are required.")
		elif region_mode != "Snyk region (recommended)" and not (broker_server_url or "").strip():
			st.error("For a custom API URL, enter the Broker server URL used for BROKER_SERVER_URL in docker (see Snyk regional docs).")
		else:
			# SNYK-US-01 uses default broker server in the image; US-02 / EU / AU need -e BROKER_SERVER_URL.
			# Custom API URL always needs an explicit broker server URL when generating docker.
			docker_include_broker: bool
			snyk_preset_key: Optional[str] = None
			if region_mode == "Snyk region (recommended)":
				snyk_preset_key = region_choice
				docker_include_broker = region_choice != "SNYK-US-01 (default US)"
			else:
				docker_include_broker = True
			updates: Dict[str, Any] = {
				"region_url": region_url.rstrip("/"),
				"api_token": api_token,
				"verify_ssl": verify_ssl,
				"ssl_cert_path": ssl_cert_path.strip() or None,
				"broker_server_url": (broker_server_url or "").strip() or None,
				"snyk_region_preset_key": snyk_preset_key,
				"docker_include_broker_server_url": docker_include_broker,
				"install_id": install_id.strip() or None,
				"deployment_id": deployment_id.strip() or None,
				"connection_id": connection_id_resume.strip() or None,
				"client_id": client_id.strip() or None,
				"client_secret": client_secret.strip() or None,
			}
			tid = (tenant_manual or "").strip()
			if tid:
				updates["tenant_id"] = tid
			st.session_state.state.update(updates)
			st.success("Session saved. Select a tenant below if you did not enter a Tenant ID.")

# Tenant discovery (requires API URL + token; tenant_id may be empty on first load)
has_api = bool(st.session_state.state.get("region_url")) and bool(st.session_state.state.get("api_token"))
if has_api and not (st.session_state.state.get("tenant_id") or "").strip():
	st.subheader("Select tenant")
	_t_client = UniversalBrokerClient(
		region_url=st.session_state.state["region_url"],
		api_token=st.session_state.state["api_token"],
		tenant_id="",
		verify_ssl=st.session_state.state.get("verify_ssl", True),
		ssl_cert_path=st.session_state.state.get("ssl_cert_path"),
	)
	try:
		tenants_resp = _t_client.list_tenants()
		raw = tenants_resp.get("data") or tenants_resp.get("tenants") or []
		tenant_options: List[Tuple[str, str]] = []
		for t in raw:
			if not isinstance(t, dict):
				continue
			tid = t.get("id")
			if not tid:
				continue
			tname = None
			attr = t.get("attributes")
			if isinstance(attr, dict):
				tname = attr.get("name") or attr.get("slug")
			label = f"{tname} ({tid})" if tname else str(tid)
			tenant_options.append((tid, label))
		if tenant_options:
			labels = [x[1] for x in tenant_options]
			ids = [x[0] for x in tenant_options]
			chosen_label = st.selectbox("Tenant", options=labels)
			chosen_idx = labels.index(chosen_label)
			if st.button("Use selected tenant"):
				st.session_state.state["tenant_id"] = ids[chosen_idx]
				st.success("Tenant selected.")
				st.rerun()
		else:
			st.warning("No tenants returned by GET /tenants. Enter your Tenant ID manually in **Initialize session** and click Initialize again.")
	except Exception as e:
		st.error(f"Could not list tenants: {e}")
		st.info("Enter your Tenant ID manually under **Initialize session** if listing fails.")

ready = bool(st.session_state.state.get("region_url")) and bool(st.session_state.state.get("api_token")) and bool((st.session_state.state.get("tenant_id") or "").strip())

if not ready:
	st.info("Complete **Initialize session** and choose a **tenant** (or enter Tenant ID) to continue.")
	st.stop()

if ready:
	client = UniversalBrokerClient(
		region_url=st.session_state.state["region_url"],
		api_token=st.session_state.state["api_token"],
		tenant_id=st.session_state.state["tenant_id"],
		verify_ssl=st.session_state.state.get("verify_ssl", True),
		ssl_cert_path=st.session_state.state.get("ssl_cert_path")
	)

	st.header("Select Group, then Organization")
	# 1) Select and save Group (this dropdown is populated with Groups only)
	with st.form("group_select_form"):
		try:
			groups_data = client.list_groups(limit=100)
			groups = groups_data.get("data") or groups_data.get("groups") or []
			# Support JSON:API-style payloads where attributes carry the name
			group_options = []
			for g in groups:
				gid = g.get("id") or g.get("group_id")
				gname = g.get("name") or (g.get("attributes", {}).get("name") if isinstance(g.get("attributes"), dict) else None)
				if gid:
					group_options.append((gid, gname or gid))
			group_map = {f"{_sanitize_label(name)} ({gid})": gid for gid, name in group_options if gid and name}
		except Exception as e:
			group_map = {}
			st.error(f"Failed to load groups: {e}")

		group_label = st.selectbox("Select Group (from your accessible Groups)", options=list(group_map.keys())) if group_map else st.text_input("Group ID (manual)")
		selected_group_id = group_map.get(group_label, group_label)
		submit_group = st.form_submit_button("Use Group")
		if submit_group:
			if selected_group_id:
				st.session_state.state["group_id"] = selected_group_id
				# Reset any previously selected organization when group changes
				st.session_state.state["org_id"] = None
				st.success(f"Selected group: {selected_group_id}")
			else:
				st.error("Please select or enter a Group ID.")

	# 2) Once group is set, select and save Organization
	if st.session_state.state.get("group_id"):
		with st.form("org_select_form"):
			group_id_for_orgs = st.session_state.state.get("group_id")
			try:
				orgs_data = client.list_orgs_in_group(group_id_for_orgs, limit=100)
				orgs = orgs_data.get("data") or orgs_data.get("orgs") or []
				org_options = []
				for o in orgs:
					oid = o.get("id") or o.get("org_id")
					oname = o.get("name") or (o.get("attributes", {}).get("name") if isinstance(o.get("attributes"), dict) else None)
					if oid:
						org_options.append((oid, oname or oid))
				org_map = {f"{_sanitize_label(name)} ({oid})": oid for oid, name in org_options if oid and name}
			except Exception as e:
				org_map = {}
				st.error(f"Failed to load organizations for group {group_id_for_orgs}: {e}")

			org_label = st.selectbox("Select Organization for App Install", options=list(org_map.keys())) if org_map else st.text_input("Organization ID (manual)")
			selected_org_id = org_map.get(org_label, org_label)
			submit_org = st.form_submit_button("Use Organization")
			if submit_org:
				if selected_org_id:
					st.session_state.state["org_id"] = selected_org_id
					st.success(f"Selected org: {selected_org_id}")
				else:
					st.error("Please select or enter an Organization ID.")

	# 3) Install Universal Broker App in selected organization
	if st.session_state.state.get("org_id"):
		with st.form("install_app_form"):
			st.write("Install the Universal Broker App into the selected organization.")
			override_app_id = st.text_input("App ID (optional)", value="cb43d761-bd17-4b44-9b6c-e5b8ad077d33")
			install_submit = st.form_submit_button("Install Universal Broker App")
			if install_submit:
				try:
					install_resp = client.install_universal_broker_app(st.session_state.state["org_id"], app_id=override_app_id or "cb43d761-bd17-4b44-9b6c-e5b8ad077d33")
				
					# Extract IDs from JSON:API response format
					install_id = install_resp.get("data", {}).get("id")
					attributes = install_resp.get("data", {}).get("attributes", {})
					client_id_v = attributes.get("client_id")
					client_secret_v = attributes.get("client_secret")
				
					# Store in session state
					if install_id:
						st.session_state.state["install_id"] = install_id
					if client_id_v:
						st.session_state.state["client_id"] = client_id_v
					if client_secret_v:
						st.session_state.state["client_secret"] = client_secret_v
				
					# Display the extracted values clearly
					st.success("App installed successfully!")
					if install_id:
						st.info(f"**Install ID:** `{install_id}`")
					if client_id_v:
						st.info(f"**Client ID:** `{client_id_v}`")
					if client_secret_v:
						st.info(f"**Client Secret:** `{client_secret_v}`")
				
					# Show full response in expandable section
					with st.expander("Full API Response", expanded=False):
						st.json(install_resp)
					
				except Exception as e:
					st.error(f"Failed to install app: {e}")

	st.header("Create Deployment")
	with st.form("deployment_form"):
		install_id_input = st.text_input("Install ID", value=st.session_state.state.get("install_id") or "")
		org_id_for_deployment = st.text_input("Organization ID for Broker App Install", value=st.session_state.state.get("org_id") or "")
		deployment_name = st.text_input("Deployment Name", placeholder="My Universal Broker Deployment")
		cluster_input = st.text_input("Cluster / notes (optional)", placeholder="Cluster X Region Y", help="Stored in deployment metadata as cluster (see Snyk docs).")
		create_dep = st.form_submit_button("Create / Use Deployment")
		if create_dep:
			if install_id_input and (st.session_state.state.get("deployment_id") or (org_id_for_deployment and deployment_name)):
				st.session_state.state["install_id"] = install_id_input
				if st.session_state.state.get("deployment_id"):
					st.info("Using existing Deployment ID from session.")
				else:
					cluster = cluster_input.strip() if cluster_input.strip() else ""
					dep = client.create_broker_deployment(install_id_input, org_id_for_deployment, deployment_name, cluster)
					deployment_id = dep.get("data", {}).get("id")
					if deployment_id:
						st.session_state.state["deployment_id"] = deployment_id
						st.success("Deployment created successfully!")
						st.info(f"**Deployment ID:** `{deployment_id}`")
					
						# Show full response in expandable section
						with st.expander("Full API Response", expanded=False):
							st.json(dep)
					else:
						st.error("Failed to extract Deployment ID from response")
						st.json(dep)
			else:
				st.error("Install ID, Org ID, and Deployment Name are required to create a deployment.")

	st.header("Manage Deployment Credentials")

	# Define connection types for credential creation (same as connection creation)
	non_cr_connections = [
		"artifactory", "azure-repos", "bitbucket-server", "github", "github-enterprise", 
		"github-server-app", "github-cloud-app", "gitlab", "jira", "nexus"
	]
	cr_connections = [
		"acr", "artifactory-cr", "digitalocean-cr", "docker-hub", "ecr", "gcr", 
		"github-cr", "gitlab-cr", "google-artifact-cr", "harbor-cr", "nexus-cr", "quay-cr"
	]
	credential_types = non_cr_connections + cr_connections

	with st.form("credentials_form"):
		install_id_creds = st.text_input("Install ID", value=st.session_state.state.get("install_id") or "")
		deployment_id_creds = st.text_input("Deployment ID", value=st.session_state.state.get("deployment_id") or "")
	
		# Add credential type selection using the same types as connection creation
		cred_type = st.selectbox("Credential Type", options=credential_types, help="Select the type of credential you're creating")
		cred_key = st.text_input("Credential Key", placeholder="e.g., GITHUB_TOKEN, JIRA_PASSWORD")
		cred_comment = st.text_input("Comment (optional)", placeholder="Credential reference for GITHUB_TOKEN", help="Optional comment describing this credential")
		st.info("💡 Credentials are references only. The actual secret values will be provided as environment variables when running the docker container.")
		add_cred = st.form_submit_button("Add Credential")
	
		if add_cred:
			if install_id_creds and deployment_id_creds and cred_key and cred_type:
				try:
					created = client.create_deployment_credential(install_id_creds, deployment_id_creds, key=cred_key, comment=cred_comment, cred_type=cred_type)
					credential_id = _credential_id_from_create_response(created)
					if credential_id:
						# Get full credential details using the API
						try:
							credential_details = client.get_deployment_credential(install_id_creds, deployment_id_creds, credential_id)
							st.success("Credential reference added successfully!")
							st.info(f"**Credential ID:** `{credential_id}`")
						
							# Store credential ID in session state for use in connection creation
							if "credential_ids" not in st.session_state.state:
								st.session_state.state["credential_ids"] = {}
							st.session_state.state["credential_ids"][cred_key] = {
								"id": credential_id,
								"type": cred_type,
								"comment": cred_comment
							}
						
							# Show credential details
							with st.expander("Credential Details", expanded=True):
								st.json(credential_details)
						
							# Show full creation response in expandable section
							with st.expander("Full Creation API Response", expanded=False):
								st.json(created)
						except Exception as e:
							st.warning(f"Credential created but could not retrieve details: {e}")
							st.info(f"**Credential ID:** `{credential_id}`")
						
							# Still store the credential ID even if we can't get details
							if "credential_ids" not in st.session_state.state:
								st.session_state.state["credential_ids"] = {}
							st.session_state.state["credential_ids"][cred_key] = {
								"id": credential_id,
								"type": cred_type,
								"comment": cred_comment
							}
					else:
						st.error("Failed to extract Credential ID from response")
						st.json(created)
				except Exception as e:
					st.error(f"Failed to add credential: {e}")
			else:
				st.error("Install ID, Deployment ID, Credential Type, and Credential Key are required.")

	# List existing credentials
	if st.session_state.state.get("install_id") and st.session_state.state.get("deployment_id"):
		try:
			existing_creds = client.list_deployment_credentials(st.session_state.state["install_id"], st.session_state.state["deployment_id"])
			if existing_creds.get("data"):
				st.write("**Existing Credentials:**")
				for cred in existing_creds["data"]:
					cred_name = UniversalBrokerClient.credential_env_name(cred) or "Unknown"
					cred_id = cred.get("id", "No ID") if isinstance(cred, dict) else "No ID"
					attrs = cred.get("attributes", {}) if isinstance(cred, dict) else {}
					cred_comment = (attrs.get("comment") if isinstance(attrs, dict) else None) or (cred.get("comment", "") if isinstance(cred, dict) else "")
					if cred_comment:
						st.write(f"- **{cred_name}** (ID: {cred_id}) - {cred_comment}")
					else:
						st.write(f"- **{cred_name}** (ID: {cred_id})")
		except Exception as e:
			st.warning(f"Could not load existing credentials: {e}")

	# Display available credential IDs for connection creation
	if st.session_state.state.get("credential_ids"):
		st.write("**Available Credential IDs for Connection Creation:**")
		for cred_key, cred_info in st.session_state.state["credential_ids"].items():
			st.write(f"- **{cred_key}**: `{cred_info['id']}` (Type: {cred_info['type']})")

	st.header("Create Connection")

	# Use the same connection types defined earlier for credential creation
	connection_types = credential_types

	# Connection type selection outside of form to enable dynamic updates
	connection_type = st.selectbox("Connection Type", options=connection_types, key="connection_type_select")

	# Show dynamic fields based on selected connection type
	config_fields = _get_connection_config_fields(connection_type)
	if config_fields:
		st.write(f"**Configuration for {connection_type}:**")
	
		# Store config values in session state for form submission
		if f"conn_config_{connection_type}" not in st.session_state:
			st.session_state[f"conn_config_{connection_type}"] = {}
	
		config_values = {}
		auth_type = None  # Track auth type for conditional fields
	
		for field_name, field_config in config_fields.items():
			# Handle conditional fields based on auth_type
			if field_config.get("conditional"):
				if auth_type != field_config["conditional"]:
					continue
		
			# Handle select fields (like auth_type)
			if field_config["type"] == "select":
				value = st.selectbox(
					field_config["label"] + (" *" if field_config.get("required", False) else ""),
					options=field_config["options"],
					index=field_config["options"].index(field_config.get("default", field_config["options"][0])),
					key=f"conn_{field_name}_{connection_type}"
				)
				config_values[field_name] = value
				st.session_state[f"conn_config_{connection_type}"][field_name] = value
				# Store auth_type for conditional field logic
				if field_name == "auth_type":
					auth_type = value
		
			elif field_config["type"] == "text":
				help_text = field_config.get("help", "")
				# Show help text as info box for Broker Client URL
				if help_text and "broker_client_url" in field_name:
					st.info(help_text)
			
				# Check if this is a reference field that should use credential IDs
				is_reference_field = any(ref_word in field_name.lower() for ref_word in ["token", "password", "pat"])
			
				if is_reference_field and st.session_state.state.get("credential_ids"):
					# Show dropdown with available credential IDs for reference fields
					available_creds = []
					for cred_key, cred_info in st.session_state.state["credential_ids"].items():
						if cred_info["type"] == connection_type or "cr" in connection_type:
							available_creds.append(f"{cred_key} ({cred_info['id']})")
				
					if available_creds:
						selected_cred = st.selectbox(
							field_config["label"] + (" *" if field_config.get("required", False) else ""),
							options=["Manual Entry"] + available_creds,
							key=f"conn_{field_name}_{connection_type}",
							help="Select a credential ID or enter manually"
						)
					
						if selected_cred == "Manual Entry":
							value = st.text_input(
								"Manual Entry",
								placeholder=field_config.get("placeholder", ""),
								key=f"conn_{field_name}_{connection_type}_manual"
							)
						else:
							# Extract credential ID from selection
							cred_id = selected_cred.split("(")[-1].rstrip(")")
							value = cred_id
							st.info(f"Using credential ID: `{cred_id}`")
					else:
						# No matching credentials, show text input
						value = st.text_input(
							field_config["label"] + (" *" if field_config.get("required", False) else ""),
							placeholder=field_config.get("placeholder", ""),
							help=help_text if "broker_client_url" not in field_name else None,
							key=f"conn_{field_name}_{connection_type}",
							value=st.session_state[f"conn_config_{connection_type}"].get(field_name, "")
						)
				else:
					# Regular text input
					value = st.text_input(
						field_config["label"] + (" *" if field_config.get("required", False) else ""),
						placeholder=field_config.get("placeholder", ""),
						help=help_text if "broker_client_url" not in field_name else None,
						key=f"conn_{field_name}_{connection_type}",
						value=st.session_state[f"conn_config_{connection_type}"].get(field_name, "")
					)
			
				config_values[field_name] = value
				st.session_state[f"conn_config_{connection_type}"][field_name] = value
		
			elif field_config["type"] == "password":
				# Add suggestion for password fields to use credentials
				help_text = "💡 Consider using deployment credentials instead of entering secrets directly"
				value = st.text_input(
					field_config["label"] + (" *" if field_config.get("required", False) else ""),
					type="password",
					placeholder=field_config.get("placeholder", ""),
					help=help_text,
					key=f"conn_{field_name}_{connection_type}",
					value=st.session_state[f"conn_config_{connection_type}"].get(field_name, "")
				)
				config_values[field_name] = value
				st.session_state[f"conn_config_{connection_type}"][field_name] = value
	else:
		st.warning(f"No specific configuration fields defined for {connection_type}. You may need to configure this manually.")
		config_values = {}

	# Connection creation form
	with st.form("connection_form"):
		install_id_val = st.text_input("Install ID", value=st.session_state.state.get("install_id") or "")
		deployment_id_val = st.text_input("Deployment ID", value=st.session_state.state.get("deployment_id") or "")
		connection_name = st.text_input("Connection Name")
	
		create_conn = st.form_submit_button("Create Connection")
		if create_conn:
			# Use the current connection type and config values from session state
			current_connection_type = st.session_state.get("connection_type_select", connection_types[0])
			current_config_fields = _get_connection_config_fields(current_connection_type)
			current_config_values = st.session_state.get(f"conn_config_{current_connection_type}", {})
		
			# Filter out empty values, trim whitespace, and validate required fields
			config = {k: v.strip() for k, v in current_config_values.items() if v and v.strip()}
			missing_required = [k for k, v in current_config_fields.items() if v.get("required", False) and not config.get(k)]
		
			if install_id_val and deployment_id_val and current_connection_type and connection_name and not missing_required:
				try:
					conn = client.create_broker_connection(install_id_val, deployment_id_val, connection_type=current_connection_type, name=connection_name, config=config)
					# Extract connection ID from response - could be in data.id or just id
					connection_id = conn.get("data", {}).get("id") or conn.get("id") or conn.get("connection_id")
					if connection_id:
						st.session_state.state["connection_id"] = connection_id
						st.session_state.state["connection_type"] = current_connection_type
						st.success("Connection created successfully!")
						st.info(f"**Connection ID:** `{connection_id}`")
					
						# Show full response in expandable section
						with st.expander("Full API Response", expanded=False):
							st.json(conn)
					else:
						st.error("Failed to extract Connection ID from response")
						st.json(conn)
				except Exception as e:
					st.error(f"Failed to create connection: {e}")
					# Show debug info in expandable section
					with st.expander("Debug Information", expanded=True):
						st.write(f"Connection Type: {current_connection_type}")
						st.write(f"Connection Name: {connection_name}")
						st.write(f"Config: {config}")
						st.write(f"Error: {str(e)}")
			else:
				if missing_required:
					st.error(f"Missing required fields: {', '.join(missing_required)}")
				else:
					st.error("Install ID, Deployment ID, Connection Type, and Connection Name are required.")

	st.header("Integrate Connection with Organization")
	st.caption(
		f"API path uses your tenant ID `{st.session_state.state.get('tenant_id', '')}` plus connection ID, target org ID, and body type."
	)
	integration_org_map: Dict[str, str] = {}
	group_for_integration = st.session_state.state.get("group_id")
	if group_for_integration:
		try:
			orgs_data_i = client.list_orgs_in_group(group_for_integration, limit=100)
			orgs_i = orgs_data_i.get("data") or orgs_data_i.get("orgs") or []
			for o in orgs_i:
				if not isinstance(o, dict):
					continue
				oid = o.get("id") or o.get("org_id")
				oname = o.get("name") or (o.get("attributes", {}).get("name") if isinstance(o.get("attributes"), dict) else None)
				if oid:
					label_i = f"{_sanitize_label(oname or oid)} ({oid})"
					integration_org_map[label_i] = oid
		except Exception as e:
			st.warning(f"Could not load organizations for integration picker: {e}")

	with st.form("integration_form"):
		connection_id_val = st.text_input("Connection ID", value=st.session_state.state.get("connection_id") or "")
		org_source = st.radio(
			"Target organization",
			("Choose from list", "Enter organization ID manually"),
			horizontal=True,
			help="You can link this connection to a different org than the one used for app install.",
		)
		org_id_val = ""
		if org_source == "Choose from list" and integration_org_map:
			org_labels_i = list(integration_org_map.keys())
			default_org = st.session_state.state.get("org_id") or ""
			default_idx = 0
			for idx, lbl in enumerate(org_labels_i):
				if integration_org_map[lbl] == default_org:
					default_idx = idx
					break
			org_choice_label = st.selectbox("Organization", options=org_labels_i, index=default_idx)
			org_id_val = integration_org_map[org_choice_label]
		else:
			if org_source == "Choose from list" and not integration_org_map:
				st.info("No org list available (set a **Group** above or enter an org ID manually).")
			org_id_val = st.text_input(
				"Organization ID",
				value=st.session_state.state.get("org_id") or "",
				help="UUID of the Snyk organization to attach this broker connection to.",
			)

		stored_connection_type = st.session_state.state.get("connection_type")
		default_index = connection_types.index(stored_connection_type) if stored_connection_type in connection_types else 0
		connection_type_val = st.selectbox(
			"Connection type (request body)",
			options=connection_types,
			index=default_index,
			help="Must match the connection you created (e.g. github). Sent as data.type in the API body.",
		)
		optional_integration_id = st.text_input(
			"Optional: integration ID",
			placeholder="Leave empty unless your tenant requires linking an existing org integration UUID",
			help="Optional field data.integration_id in the API. Omit for the common case.",
		)
		integrate = st.form_submit_button("Integrate Connection")
		if integrate:
			oid = (org_id_val or "").strip()
			if connection_id_val and oid and connection_type_val:
				try:
					integration = client.create_broker_connection_integration(
						connection_id_val.strip(),
						oid,
						connection_type_val,
						integration_id=(optional_integration_id or "").strip() or None,
					)
					st.session_state.state["integration_target_org_id"] = oid
					st.session_state.state["org_integration_linked_id"] = (
						integration.get("data", {}).get("id") or integration.get("id") or integration.get("integration_id")
					)
					st.success("Integration linked successfully.")
					with st.expander("API response", expanded=False):
						st.json(integration)
				except Exception as e:
					st.error(f"Failed to create integration: {e}")
					with st.expander("Debug Information", expanded=False):
						st.write(f"**Tenant ID:** {st.session_state.state.get('tenant_id')}")
						st.write(f"**Connection ID:** {connection_id_val}")
						st.write(f"**Organization ID:** {oid}")
						st.write(f"**Connection type:** {connection_type_val}")
						st.write(f"**Optional integration_id:** {optional_integration_id or '(none)'}")
						st.write(f"**Error:** {str(e)}")
			else:
				st.error("Connection ID, Organization ID, and connection type are required.")

	st.header("Generate Docker Command")
	with st.form("docker_form"):
		install_id_v = st.text_input("Install ID", value=st.session_state.state.get("install_id") or "")
		deployment_id_v = st.text_input("Deployment ID", value=st.session_state.state.get("deployment_id") or "")
		client_id_v = st.text_input("Client ID", value=st.session_state.state.get("client_id") or "")
		client_secret_v = st.text_input("Client Secret", type="password", value=st.session_state.state.get("client_secret") or "")
	
		# Load existing credentials for docker command
		existing_creds_for_docker: List[Tuple[str, str]] = []
		if install_id_v and deployment_id_v:
			try:
				creds_data = client.list_deployment_credentials(install_id_v, deployment_id_v)
				if creds_data.get("data"):
					for cred in creds_data["data"]:
						key = UniversalBrokerClient.credential_env_name(cred)
						if key:
							existing_creds_for_docker.append((key, f"<{key}_VALUE>"))
			except Exception:
				pass
	
		generate = st.form_submit_button("Generate Docker Command")
		if generate:
			if deployment_id_v and client_id_v and client_secret_v:
				include_broker = st.session_state.state.get("docker_include_broker_server_url")
				if include_broker is None:
					include_broker = st.session_state.state.get("snyk_region_preset_key") != "SNYK-US-01 (default US)"
				broker_u = (
					(st.session_state.state.get("broker_server_url") or "").strip() or None
					if include_broker
					else None
				)
				cmd = UniversalBrokerClient.build_docker_run_command(
					deployment_id_v,
					client_id_v,
					client_secret_v,
					existing_creds_for_docker,
					broker_server_url=broker_u,
				)
				st.code(cmd, language="bash")
				st.success("Copy and store these values securely.")
				if not broker_u and not include_broker:
					st.caption(
						"BROKER_SERVER_URL omitted — not required for SNYK-US-01 (default broker host). "
						"US-02, EU, and AU include it automatically when you pick that region at session start."
					)
				st.info("Replace `<ENV_NAME_VALUE>` placeholders with your real secret values. Restart the broker container after changing credential env vars.")
			else:
				st.error("Deployment ID, Client ID, and Client Secret are required.")

	st.caption("You can start at any step by providing the relevant IDs above.")
