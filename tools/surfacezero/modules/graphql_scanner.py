"""
Module: graphql
GraphQL attack surface enumeration:
- Detects GraphQL endpoints
- Schema introspection (full + partial)
- Dangerous mutation enumeration
- Unauthenticated query probing
- Batch query abuse detection
- Field suggestion extraction
"""

import asyncio
import json
from typing import List, Dict, Optional
from modules.http_client import HTTPClient


# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
    "/data",
    "/graph",
    "/hasura/v1/graphql",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}
"""

# Lightweight introspection for cases where full is blocked
PARTIAL_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
    }
    queryType { name }
    mutationType { name }
  }
}
"""

# Field suggestion probe (typo to trigger suggestions)
FIELD_SUGGESTION_QUERY = """
{ __typenme }
"""

# Sensitive mutation/query patterns
SENSITIVE_PATTERNS = [
    "createUser", "deleteUser", "updateUser", "registerUser",
    "resetPassword", "changePassword", "forgotPassword",
    "login", "logout", "authenticate", "refreshToken",
    "uploadFile", "deleteFile",
    "adminQuery", "internalQuery",
    "exportData", "downloadData",
    "createAdmin", "promoteUser", "setRole",
    "bypassAuth", "skipVerification",
    "transferFunds", "makePayment",
    "sendEmail", "sendSMS",
    "webhook", "executeScript",
    "rawQuery", "runQuery",
]


class GraphQLScanner:
    """GraphQL endpoint discovery and attack surface enumeration."""

    def __init__(self, config: dict):
        self.config = config
        self.client = HTTPClient(config)
        self.base_url = config.get("target", "").rstrip("/")

    async def _probe_endpoint(self, path: str) -> Optional[Dict]:
        """Probe a single path for GraphQL endpoint."""
        url = self.base_url + path

        # Try GET first (introspection)
        resp = await self.client.get(
            url,
            extra_headers={"Content-Type": "application/json", "Accept": "application/json"}
        )

        # Try POST with introspection
        resp_post = await self.client.post(
            url,
            json={"query": "{ __typename }"},
            extra_headers={"Content-Type": "application/json"}
        )

        if resp_post and resp_post.status_code in [200, 400]:
            try:
                data = resp_post.json()
                if "data" in data or "errors" in data:
                    return {"url": url, "method": "POST", "status": resp_post.status_code}
            except Exception:
                pass

        if resp and resp.status_code in [200, 400]:
            try:
                data = resp.json()
                if "data" in data or "errors" in data:
                    return {"url": url, "method": "GET", "status": resp.status_code}
            except Exception:
                pass

        return None

    async def _run_introspection(self, gql_url: str) -> Optional[Dict]:
        """Attempt full schema introspection."""
        resp = await self.client.post(
            gql_url,
            json={"query": INTROSPECTION_QUERY},
            extra_headers={"Content-Type": "application/json"}
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data and data["data"] and "__schema" in data["data"]:
                    return data["data"]["__schema"]
            except Exception:
                pass

        # Try partial if full is blocked
        resp2 = await self.client.post(
            gql_url,
            json={"query": PARTIAL_INTROSPECTION_QUERY},
            extra_headers={"Content-Type": "application/json"}
        )
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                if "data" in data and data["data"] and "__schema" in data["data"]:
                    return data["data"]["__schema"]
            except Exception:
                pass

        return None

    async def _probe_field_suggestions(self, gql_url: str) -> bool:
        resp = await self.client.post(
            gql_url,
            json={"query": FIELD_SUGGESTION_QUERY},
            extra_headers={"Content-Type": "application/json"}
        )
        if resp:
            try:
                data = resp.json()
                errors = data.get("errors", [])
                for err in errors:
                    msg = err.get("message", "")
                    if "Did you mean" in msg or "suggestion" in msg.lower():
                        return True
            except Exception:
                pass
        return False

    async def _test_batch_query(self, gql_url: str) -> bool:
        """Test if batch queries are allowed (DoS / auth bypass potential)."""
        batch_payload = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        resp = await self.client.post(
            gql_url,
            json=batch_payload,
            extra_headers={"Content-Type": "application/json"}
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) == 3:
                    return True
            except Exception:
                pass
        return False

    def _analyze_schema(self, schema: Dict) -> Dict:
        """Extract queries, mutations, sensitive operations from schema."""
        queries = []
        mutations = []
        sensitive_ops = []
        types = schema.get("types", [])

        # Find query and mutation root type names
        query_root = schema.get("queryType", {}) or {}
        mutation_root = schema.get("mutationType", {}) or {}

        for t in types:
            if not t or t.get("name", "").startswith("__"):
                continue
            fields = t.get("fields") or []
            for field in fields:
                fname = field.get("name", "")
                if t["name"] == query_root.get("name"):
                    queries.append(fname)
                elif t["name"] == mutation_root.get("name"):
                    mutations.append(fname)

                # Check against sensitive patterns
                for sp in SENSITIVE_PATTERNS:
                    if sp.lower() in fname.lower():
                        sensitive_ops.append({
                            "operation": fname,
                            "parent_type": t["name"],
                            "risk": "HIGH",
                            "reason": f"Matches sensitive pattern: {sp}",
                        })

        return {
            "query_count": len(queries),
            "mutation_count": len(mutations),
            "queries": queries[:50],  # Cap for readability
            "mutations": mutations[:50],
            "sensitive_operations": sensitive_ops,
            "type_count": len(types),
        }

    async def run(self) -> Dict:
        """Full GraphQL enumeration pipeline."""
        # 1. Discover endpoints
        tasks = [self._probe_endpoint(path) for path in GRAPHQL_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        discovered = [r for r in results if isinstance(r, dict) and r is not None]

        if not discovered:
            return {
                "module": "graphql",
                "endpoints_found": [],
                "introspection_enabled": False,
                "schema": None,
                "batch_queries_allowed": False,
                "field_suggestions": False,
                "sensitive_operations": [],
                "summary": "No GraphQL endpoints detected.",
            }

        # 2. For each discovered endpoint, run full analysis
        all_schemas = []
        any_introspection = False
        any_batch = False
        any_suggestions = False
        sensitive_ops = []

        for ep in discovered:
            gql_url = ep["url"]

            schema = await self._run_introspection(gql_url)
            if schema:
                any_introspection = True
                analysis = self._analyze_schema(schema)
                all_schemas.append({"endpoint": gql_url, "analysis": analysis})
                sensitive_ops.extend(analysis.get("sensitive_operations", []))

            batch = await self._test_batch_query(gql_url)
            if batch:
                any_batch = True

            suggestions = await self._probe_field_suggestions(gql_url)
            if suggestions:
                any_suggestions = True

        return {
            "module": "graphql",
            "endpoints_found": discovered,
            "introspection_enabled": any_introspection,
            "schema_analysis": all_schemas,
            "batch_queries_allowed": any_batch,
            "field_suggestions_enabled": any_suggestions,
            "sensitive_operations": sensitive_ops,
            "total_sensitive": len(sensitive_ops),
        }
