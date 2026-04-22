import requests
import ssl
import urllib3
from typing import Any, Dict, List, Optional, Tuple

# Default REST API version (see Universal Broker docs)
DEFAULT_REST_VERSION = "2025-11-05"


class UniversalBrokerClient:
	def __init__(self, region_url: str, api_token: str, tenant_id: str, timeout_seconds: int = 30, verify_ssl: bool = True, ssl_cert_path: Optional[str] = None) -> None:
		self.base_url = region_url.rstrip('/')
		self.api_token = api_token
		self.tenant_id = tenant_id
		self.verify_ssl = verify_ssl
		self.ssl_cert_path = ssl_cert_path
		self.session = requests.Session()
		self.session.headers.update({
			"Authorization": f"token {self.api_token}",
			"Content-Type": "application/vnd.api+json",
			"Accept": "application/vnd.api+json",
		})
		self.timeout = timeout_seconds
		
		# Configure SSL settings
		if not verify_ssl:
			# Disable SSL warnings when verification is disabled
			urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
			self.session.verify = False
		elif ssl_cert_path:
			# Use custom certificate path
			self.session.verify = ssl_cert_path
		else:
			# Use default SSL verification
			self.session.verify = True

	def _url(self, path: str) -> str:
		# Ensure we always call REST API under /rest
		normalized = path if path.startswith("/rest/") else ("/rest" + (path if path.startswith("/") else f"/{path}"))
		return f"{self.base_url}{normalized}"

	def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> requests.Response:
		merged_params: Dict[str, Any] = {}
		if params:
			merged_params.update(params)
		# Ensure REST API version is always present unless explicitly overridden
		merged_params.setdefault("version", DEFAULT_REST_VERSION)
		request_method = getattr(self.session, method.lower())
		request_headers = None
		if headers:
			request_headers = {**self.session.headers, **headers}
		
		# Ensure SSL verification settings are passed to the request
		request_kwargs = {
			"params": merged_params,
			"headers": request_headers,
			"timeout": self.timeout,
			"verify": self.session.verify,
			**kwargs
		}
		
		resp = request_method(self._url(path), **request_kwargs)
		resp.encoding = "utf-8"
		try:
			resp.raise_for_status()
		except requests.HTTPError as e:
			body = ""
			if e.response is not None:
				body = (e.response.text or "")[:4000]
			msg = f"{e}\nResponse body: {body}" if body else str(e)
			raise requests.HTTPError(msg, response=e.response) from e
		return resp

	@staticmethod
	def snyk_region_presets() -> Dict[str, Tuple[str, str]]:
		"""Region label -> (REST API base URL, Broker server URL for docker BROKER_SERVER_URL).

		See https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency
		"""
		return {
			"SNYK-US-01 (default US)": ("https://api.snyk.io", "https://broker.snyk.io"),
			"SNYK-US-02": ("https://api.us.snyk.io", "https://broker.us.snyk.io"),
			"SNYK-EU-01": ("https://api.eu.snyk.io", "https://broker.eu.snyk.io"),
			"SNYK-AU-01": ("https://api.au.snyk.io", "https://broker.au.snyk.io"),
		}

	@staticmethod
	def credential_env_name(item: Any) -> Optional[str]:
		"""Resolve environment variable name from a credential list item (JSON:API or flat)."""
		if not isinstance(item, dict):
			return None
		attrs = item.get("attributes")
		if isinstance(attrs, dict):
			name = attrs.get("environment_variable_name")
			if name:
				return str(name)
		name = item.get("environment_variable_name") or item.get("key")
		return str(name) if name else None

	# Helper endpoints for discovery
	def list_tenants(self) -> Dict[str, Any]:
		resp = self._request("get", "/tenants")
		return resp.json()

	def list_groups(self, starting_after: Optional[str] = None, ending_before: Optional[str] = None, limit: Optional[int] = None) -> Dict[str, Any]:
		params: Dict[str, Any] = {}
		if starting_after:
			params["starting_after"] = starting_after
		if ending_before:
			params["ending_before"] = ending_before
		# Always constrain page size to 100
		params["limit"] = 100
		resp = self._request("get", "/groups", params=params)
		return resp.json()

	def list_orgs_in_group(self, group_id: str, version: Optional[str] = None, q: Optional[str] = None, sort_by: Optional[str] = None, sort_order: Optional[str] = None, limit: Optional[int] = None, starting_after: Optional[str] = None) -> Dict[str, Any]:
		params: Dict[str, Any] = {}
		if version:
			params["version"] = version
		if q:
			params["q"] = q
		if sort_by:
			params["sortBy"] = sort_by
		if sort_order:
			params["sortOrder"] = sort_order
		# Always constrain page size to 100
		params["limit"] = 100
		if starting_after:
			params["starting_after"] = starting_after
		resp = self._request("get", f"/groups/{group_id}/orgs", params=params)
		return resp.json()

	# Universal Broker - installs / deployments / connections / credentials / integrations
	def list_broker_deployments_for_tenant(self) -> Dict[str, Any]:
		resp = self._request("get", f"/tenants/{self.tenant_id}/brokers/deployments")
		return resp.json()

	def list_broker_deployments(self, install_id: str) -> Dict[str, Any]:
		resp = self._request("get", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments")
		return resp.json()

	def create_broker_deployment(self, install_id: str, org_id: str, deployment_name: str, cluster: str = "") -> Dict[str, Any]:
		metadata_obj: Dict[str, Any] = {"deployment_name": deployment_name.strip()}
		if cluster and cluster.strip():
			metadata_obj["cluster"] = cluster.strip()

		payload: Dict[str, Any] = {
			"data": {
				"type": "broker_deployment",
				"attributes": {
					"broker_app_installed_in_org_id": org_id,
					"metadata": metadata_obj
				}
			}
		}
		headers = {
			"Accept": "application/vnd.api+json",
			"Content-Type": "application/vnd.api+json",
		}
		resp = self._request("post", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments", headers=headers, json=payload)
		return resp.json()

	def update_broker_deployment(self, install_id: str, deployment_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
		resp = self._request("patch", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}", json=updates)
		return resp.json()

	def delete_broker_deployment(self, install_id: str, deployment_id: str) -> None:
		resp = self._request("delete", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}")

	def list_broker_connections(self, install_id: str, deployment_id: str) -> Dict[str, Any]:
		resp = self._request("get", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/connections")
		return resp.json()

	def create_broker_connection(self, install_id: str, deployment_id: str, connection_type: str, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
		# Based on the working curl example provided by the user
		payload = {
			"data": {
				"attributes": {
					"deployment_id": deployment_id,
					"name": name,
					"configuration": {
						"required": config,
						"type": connection_type
					}
				},
				"type": "broker_connection"
			}
		}
		headers = {
			"Accept": "application/vnd.api+json",
			"Content-Type": "application/vnd.api+json",
		}
		
		resp = self._request("post", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/connections", headers=headers, json=payload)
		return resp.json()

	def get_broker_connection(self, install_id: str, deployment_id: str, connection_id: str) -> Dict[str, Any]:
		resp = self._request("get", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/connections/{connection_id}")
		return resp.json()

	def update_broker_connection(self, install_id: str, deployment_id: str, connection_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
		resp = self._request("patch", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/connections/{connection_id}", json=updates)
		return resp.json()

	def delete_broker_connection(self, install_id: str, deployment_id: str, connection_id: str) -> None:
		resp = self._request("delete", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/connections/{connection_id}")

	def list_deployment_credentials(self, install_id: str, deployment_id: str) -> Dict[str, Any]:
		resp = self._request("get", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/credentials")
		return resp.json()

	def create_deployment_credential(self, install_id: str, deployment_id: str, key: str, comment: str = "", cred_type: str = "generic") -> Dict[str, Any]:
		# Use JSON:API format as per the API documentation
		# Use provided comment or default to key-based comment
		credential_comment = comment.strip() if comment and comment.strip() else f"Credential reference for {key}"
		
		payload = {
			"data": {
				"type": "deployment_credential",
				"attributes": [
					{
						"comment": credential_comment,
						"environment_variable_name": key,
						"type": cred_type
					}
				]
			}
		}
		headers = {
			"Accept": "application/vnd.api+json",
			"Content-Type": "application/vnd.api+json",
		}
		resp = self._request("post", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/credentials", headers=headers, json=payload)
		return resp.json()

	def get_deployment_credential(self, install_id: str, deployment_id: str, credential_id: str) -> Dict[str, Any]:
		resp = self._request("get", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/credentials/{credential_id}")
		return resp.json()

	def delete_deployment_credential(self, install_id: str, deployment_id: str, credential_id: str) -> None:
		resp = self._request("delete", f"/tenants/{self.tenant_id}/brokers/installs/{install_id}/deployments/{deployment_id}/credentials/{credential_id}")

	def create_broker_connection_integration(
		self,
		connection_id: str,
		org_id: str,
		connection_type: str,
		integration_id: Optional[str] = None,
	) -> Dict[str, Any]:
		# POST .../tenants/{tenant_id}/brokers/connections/{connection_id}/orgs/{org_id}/integration
		# Body: CreateBrokerConnectionIntegration — data.type required; data.integration_id optional.
		data: Dict[str, Any] = {"type": connection_type}
		if integration_id and integration_id.strip():
			data["integration_id"] = integration_id.strip()
		payload = {"data": data}
		headers = {
			"Accept": "application/vnd.api+json",
			"Content-Type": "application/vnd.api+json",
		}
		resp = self._request("post", f"/tenants/{self.tenant_id}/brokers/connections/{connection_id}/orgs/{org_id}/integration", headers=headers, json=payload)
		return resp.json()

	def delete_broker_connection_integration(self, connection_id: str, org_id: str, integration_id: str) -> None:
		resp = self._request("delete", f"/tenants/{self.tenant_id}/brokers/connections/{connection_id}/orgs/{org_id}/integrations/{integration_id}")

	# App install for organization (explicit version override per requirement)
	def install_universal_broker_app(self, org_id: str, app_id: str = "cb43d761-bd17-4b44-9b6c-e5b8ad077d33") -> Dict[str, Any]:
		# POST /orgs/{org_id}/apps/installs — OpenAPI requires top-level `data` + `relationships` (siblings).
		# See https://docs.snyk.io/snyk-api/reference/apps
		payload = {
			"data": {
				"type": "app_install",
			},
			"relationships": {
				"app": {
					"data": {
						"id": app_id,
						"type": "app",
					}
				}
			},
		}
		headers = {
			"Accept": "application/vnd.api+json",
			"Content-Type": "application/vnd.api+json",
		}
		resp = self._request("post", f"/orgs/{org_id}/apps/installs", headers=headers, json=payload)
		return resp.json()

	@staticmethod
	def build_docker_run_command(
		deployment_id: str,
		client_id: str,
		client_secret: str,
		credentials: List[Tuple[str, str]],
		port: int = 8000,
		broker_server_url: Optional[str] = None,
	) -> str:
		lines: List[str] = [
			"docker run -d --restart=always",
			f"-p {port}:{port}",
			f"-e DEPLOYMENT_ID={deployment_id}",
			f"-e CLIENT_ID={client_id}",
			f"-e CLIENT_SECRET={client_secret}",
			f"-e PORT={port}",
		]
		if broker_server_url:
			lines.append(f"-e BROKER_SERVER_URL={broker_server_url}")
		for key, value in credentials:
			lines.append(f"-e {key}={value}")
		lines.append("snyk/broker:universal")
		return " \\\n".join(lines)
