"""
AI-Driven Security Log Waste Reduction & DCR Transformation Engine
===================================================================
MCA Final-Year Project — Streamlit Dashboard

Operating model: READ-ONLY metadata ingestion only.
No write, update, or delete calls are made to Azure / Microsoft Sentinel.

Modules (in this file):
  1. Configuration & constants
  2. Read-only metadata ingestion (demo + Service Principal live sync)
  3. Correlation engine (Ghost / Waste + tiering + detection-risk notes)
  4. AI-driven KQL / DCR transformation recommendations
  5. Business case, what-if simulation, history, native recommendations
  6. Ingestion spike / anomaly & cost-creep trend engine
  7. Plotly visualization builders (cost, pie, heatmap, trend, creep)
  8. HTML / CSV / Excel exporters
  9. Streamlit UI (assessment modes, pricing, SP, tabs, export)
"""

from __future__ import annotations

import hashlib
import html
import io
import json
import math
import random
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# ---------------------------------------------------------------------------
# 1. Configuration & constants
# ---------------------------------------------------------------------------

APP_TITLE = "AI-Driven Security Log Waste Reduction & DCR Transformation Engine"
APP_SUBTITLE = (
    "Cost Governance · Ghost-Table Audit · Customer $/GB · "
    "DCR Remediation Advisory · Assessment Modes"
)

# Default indicative Analytics ingestion price (USD per GB). Customers override in UI.
DEFAULT_COST_PER_GB_USD = 2.76
# Backward-compatible alias used by older references in this module.
COST_PER_GB_USD = DEFAULT_COST_PER_GB_USD

# Local audit history (governance trend). Persisted beside the app for demos.
HISTORY_PATH = Path(__file__).resolve().parent / "data" / "audit_history.json"
HISTORY_MAX_SNAPSHOTS = 30

# Assessment mode presets (Enhancement #10)
MODE_FULL = "Full assessment"
MODE_EXEC = "Executive view"
MODE_FINOPS = "FinOps view"
MODE_SOC = "SOC view"
ASSESSMENT_MODES = [MODE_FULL, MODE_EXEC, MODE_FINOPS, MODE_SOC]

# Hardcoded demo users (MCA presentation). Replace with IdP/DB later.
# Documented in BUILD_GUIDE.md — not for production secrets management.
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
HARDCODED_USERS: dict[str, dict[str, str]] = {
    "admin": {
        "password": "Admin@123",
        "role": ROLE_ADMIN,
        "display_name": "Platform Admin",
    },
    "viewer": {
        "password": "Viewer@123",
        "role": ROLE_VIEWER,
        "display_name": "Read-Only Viewer",
    },
    "finops": {
        "password": "FinOps@123",
        "role": ROLE_VIEWER,
        "display_name": "FinOps Viewer",
    },
}

SYNC_FREQ_1H = "Every 1 hour"
SYNC_FREQ_DAILY = "Once a day"
SYNC_FREQ_WEEKLY = "Once a week"
SYNC_FREQ_MANUAL = "Manual only"
SYNC_FREQUENCY_OPTIONS = [
    SYNC_FREQ_MANUAL,
    SYNC_FREQ_1H,
    SYNC_FREQ_DAILY,
    SYNC_FREQ_WEEKLY,
]
SYNC_FREQ_SECONDS = {
    SYNC_FREQ_MANUAL: None,
    SYNC_FREQ_1H: 3600,
    SYNC_FREQ_DAILY: 86400,
    SYNC_FREQ_WEEKLY: 604800,
}

# Ingestion anomaly / trend detection thresholds (MCA-transparent heuristics)
ANOMALY_LOOKBACK_DAYS = 30
ANOMALY_MA_WINDOW = 7
ANOMALY_SPIKE_PCT = 0.50          # today > 50% above rolling baseline MA
ANOMALY_ELEVATED_PCT = 0.25       # today > 25% above baseline MA
ANOMALY_CREEP_PCT = 0.20          # window growth >= 20%
ANOMALY_TAG_NORMAL = "🟢 Normal"
ANOMALY_TAG_ELEVATED = "🟡 Elevated"
ANOMALY_TAG_SPIKE = "🚨 Anomaly / Sudden Volume Spike"

# User-selectable anomaly view windows (Apply button injects these into the engine)
ANOMALY_RANGE_1D = "1 Day"
ANOMALY_RANGE_1W = "1 Week"
ANOMALY_RANGE_1M = "1 Month"
ANOMALY_RANGE_CUSTOM = "Custom"
ANOMALY_RANGE_PRESETS = {
    ANOMALY_RANGE_1D: 1,
    ANOMALY_RANGE_1W: 7,
    ANOMALY_RANGE_1M: 30,
}

# Azure Advisor (Cost) — optional native recommendations enrichment
ARM_ADVISOR_URL = (
    "https://management.azure.com/subscriptions/{subscription_id}"
    "/providers/Microsoft.Advisor/recommendations"
    "?api-version=2023-01-01"
)

# OAuth / API scopes — read-only data plane + management plane.
LA_SCOPE = "https://api.loganalytics.azure.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"
LA_QUERY_URL = "https://api.loganalytics.azure.com/v1/workspaces/{workspace_id}/query"
ARM_ALERT_RULES_URL = (
    "https://management.azure.com/subscriptions/{subscription_id}"
    "/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
    "/providers/Microsoft.SecurityInsights/alertRules"
    "?api-version=2023-02-01"
)
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# Lookback used for Usage aggregation (Microsoft Learn style ~31-day window).
USAGE_LOOKBACK_DAYS = 30

# Microsoft Learn Usage pattern: Quantity is in MB; GB ≈ Quantity / 1000.
USAGE_KQL = """
Usage
| where TimeGenerated > ago(32d)
| where StartTime >= startofday(ago(31d)) and EndTime < startofday(now())
| where IsBillable == true
| where isnotempty(DataType)
| summarize BillableDataGB = sum(Quantity) / 1000.0 by DataType
| order by BillableDataGB desc
""".strip()


def build_usage_daily_kql(lookback_days: int = 31) -> str:
    """
    Daily billable ingest by table for Spikes & Trends (read-only Usage KQL).
    Official docs category: Microsoft Learn — Analyze usage / Usage table.
    """
    days = max(1, min(int(lookback_days), 90))
    return f"""
Usage
| where TimeGenerated > ago({days + 2}d)
| where StartTime >= startofday(ago({days}d)) and EndTime < startofday(now())
| where IsBillable == true
| where isnotempty(DataType)
| summarize BillableGB = sum(Quantity) / 1000.0 by bin(StartTime, 1d), DataType
| project Date = StartTime, TableName = DataType, BillableGB
| order by Date asc, BillableGB desc
""".strip()

# Status labels used by the correlation engine
STATUS_WASTE = "Waste / Ghost"
STATUS_ACTIVE = "Active"
STATUS_UNDERUTILIZED = "Underutilized"

# Realistic Microsoft Sentinel / Log Analytics table catalogue used for demos
# when live workspace credentials are not available.
DEMO_TABLE_CATALOGUE: list[dict[str, Any]] = [
    {
        "Table Name": "SecurityEvent",
        "Category": "Windows Security",
        "Size_GB_Day": 48.5,
        "Active Analytics Rules": 12,
    },
    {
        "Table Name": "SigninLogs",
        "Category": "Identity",
        "Size_GB_Day": 22.3,
        "Active Analytics Rules": 8,
    },
    {
        "Table Name": "AzureActivity",
        "Category": "Azure Control Plane",
        "Size_GB_Day": 6.1,
        "Active Analytics Rules": 5,
    },
    {
        "Table Name": "CommonSecurityLog",
        "Category": "Network / Firewall",
        "Size_GB_Day": 95.0,
        "Active Analytics Rules": 0,
    },
    {
        "Table Name": "Syslog",
        "Category": "Linux / Syslog",
        "Size_GB_Day": 41.2,
        "Active Analytics Rules": 0,
    },
    {
        "Table Name": "DeviceNetworkEvents",
        "Category": "Endpoint (MDE)",
        "Size_GB_Day": 18.7,
        "Active Analytics Rules": 6,
    },
    {
        "Table Name": "OfficeActivity",
        "Category": "Microsoft 365",
        "Size_GB_Day": 9.4,
        "Active Analytics Rules": 4,
    },
    {
        "Table Name": "AADNonInteractiveUserSignInLogs",
        "Category": "Identity",
        "Size_GB_Day": 31.8,
        "Active Analytics Rules": 0,
    },
    {
        "Table Name": "Heartbeat",
        "Category": "Agent Health",
        "Size_GB_Day": 2.1,
        "Active Analytics Rules": 1,
    },
    {
        "Table Name": "Perf",
        "Category": "Performance Counters",
        "Size_GB_Day": 27.6,
        "Active Analytics Rules": 0,
    },
    {
        "Table Name": "Event",
        "Category": "Windows Events",
        "Size_GB_Day": 55.0,
        "Active Analytics Rules": 2,
    },
    {
        "Table Name": "AzureDiagnostics",
        "Category": "Azure Diagnostics",
        "Size_GB_Day": 38.9,
        "Active Analytics Rules": 0,
    },
    {
        "Table Name": "DeviceProcessEvents",
        "Category": "Endpoint (MDE)",
        "Size_GB_Day": 14.2,
        "Active Analytics Rules": 7,
    },
    {
        "Table Name": "AuditLogs",
        "Category": "Identity",
        "Size_GB_Day": 4.5,
        "Active Analytics Rules": 3,
    },
    {
        "Table Name": "DnsEvents",
        "Category": "Network / DNS",
        "Size_GB_Day": 19.3,
        "Active Analytics Rules": 1,
    },
]

# AI recommendation templates keyed by table / category patterns
KQL_RECOMMENDATIONS: dict[str, dict[str, str]] = {
    "CommonSecurityLog": {
        "recommendation": (
            "High-volume CEF/firewall telemetry with zero analytics coverage. "
            "Apply DCR transformation to drop low-value Allow/Informational rows "
            "and retain Deny, Drop, and Threat signatures only."
        ),
        "kql_filter": (
            "source\n"
            "| where DeviceAction in ('Deny', 'Drop', 'Block', 'Reset')\n"
            "    or ThreatName != ''\n"
            "| project-away AdditionalExtensions, DeviceCustomString*"
        ),
    },
    "Syslog": {
        "recommendation": (
            "Syslog ingest is unused by analytics rules. Filter to security-relevant "
            "facilities/severities and drop routine daemon chatter before ingestion."
        ),
        "kql_filter": (
            "source\n"
            "| where SeverityLevel <= 3  // Emergency..Error\n"
            "    or Facility in ('auth', 'authpriv', 'security')\n"
            "| project TimeGenerated, HostName, Facility, SeverityLevel, SyslogMessage"
        ),
    },
    "AADNonInteractiveUserSignInLogs": {
        "recommendation": (
            "Non-interactive sign-in volume is large and unused. Keep failures, "
            "risky sign-ins, and privileged app traffic; drop successful service-principal noise."
        ),
        "kql_filter": (
            "source\n"
            "| where ResultType != '0'\n"
            "    or RiskLevelDuringSignIn != 'none'\n"
            "    or AppDisplayName has_any ('Azure Portal', 'Microsoft Graph')\n"
            "| project-away DeviceDetail, LocationDetails"
        ),
    },
    "Perf": {
        "recommendation": (
            "Performance counters rarely feed Sentinel detections. Prefer Azure Monitor "
            "Metrics for ops; if retained, sample critical counters only via DCR."
        ),
        "kql_filter": (
            "source\n"
            "| where ObjectName in ('Processor', 'Memory', 'LogicalDisk')\n"
            "    and CounterName in ('% Processor Time', 'Available MBytes', '% Free Space')\n"
            "| where Computer has_any ('DC-', 'SQL-', 'WEB-')"
        ),
    },
    "AzureDiagnostics": {
        "recommendation": (
            "AzureDiagnostics is a high-cardinality catch-all with no rule bindings. "
            "Split by ResourceProvider and retain only security-relevant categories "
            "(KeyVault, NSG Flow, SQL Audit)."
        ),
        "kql_filter": (
            "source\n"
            "| where Category in (\n"
            "    'AuditEvent', 'SQLSecurityAuditEvents',\n"
            "    'NetworkSecurityGroupFlowEvent', 'AzureFirewallApplicationRule'\n"
            "  )\n"
            "| project-away Properties_s"
        ),
    },
    "Event": {
        "recommendation": (
            "Windows Event table is underutilized relative to volume. Prefer SecurityEvent "
            "for detections; if Event must stay, filter to critical EventIDs only."
        ),
        "kql_filter": (
            "source\n"
            "| where EventID in (4625, 4648, 4672, 4688, 4720, 4732, 7045)\n"
            "| project TimeGenerated, Computer, EventID, EventData, UserName"
        ),
    },
    "DnsEvents": {
        "recommendation": (
            "DNS telemetry has minimal rule coverage. Keep NXDOMAIN spikes, rare domains, "
            "and known-bad indicators; drop high-frequency internal resolutions."
        ),
        "kql_filter": (
            "source\n"
            "| where ResultCode != 0\n"
            "    or Name !endswith '.corp.local'\n"
            "| summarize count() by bin(TimeGenerated, 5m), Name, ClientIP\n"
            "| where count_ > 50"
        ),
    },
}

DEFAULT_RECOMMENDATION = {
    "recommendation": (
        "No active analytics rules consume this table. Review business need; "
        "either map detections or apply a DCR transformation to reduce ingest volume."
    ),
    "kql_filter": (
        "source\n"
        "| where TimeGenerated > ago(1h)\n"
        "| take 100  // sample for schema review before designing DCR filters"
    ),
}

ACTIVE_TABLE_NOTE = {
    "recommendation": (
        "Table is bound to active analytics rules. Optimize selectively: "
        "drop unused columns and verbose debug fields while preserving detection fields."
    ),
    "kql_filter": (
        "source\n"
        "| project-away *Custom*, ExtendedProperties, AdditionalFields\n"
        "// Retain columns referenced by analytics rule queries"
    ),
}

UNDERUTILIZED_NOTE = {
    "recommendation": (
        "Volume is high relative to a small rule set. Consider tightening DCR filters "
        "around fields used by the existing analytics rules."
    ),
    "kql_filter": (
        "source\n"
        "| where TimeGenerated > ago(1d)\n"
        "| project-keep TimeGenerated, *IP*, *User*, *Host*, Action, Result\n"
        "// Align projected columns with rule KQL field usage"
    ),
}

# Tables that are often candidates for non-Analytics plans (advisory only).
BASIC_OR_AUX_CANDIDATES = {
    "Perf",
    "Heartbeat",
    "AzureDiagnostics",
    "Syslog",
    "Event",
    "CommonSecurityLog",
    "AADNonInteractiveUserSignInLogs",
}

# Demo / fallback native Microsoft-style optimization advisories (Enhancement #4).
# Used when Advisor API is unavailable; complements — does not replace — portal workbooks.
DEMO_NATIVE_RECOMMENDATIONS: list[dict[str, str]] = [
    {
        "Source": "Microsoft-style · Ingest optimization",
        "Category": "Cost",
        "Title": "Reduce high-volume unused security tables",
        "Summary": (
            "Tables with sustained billable ingest and no analytics-rule dependency "
            "are prime candidates for DCR filtering or plan review."
        ),
        "Suggested action": "Review Ghost/Waste tables in this engine; draft DCR transforms before portal changes.",
    },
    {
        "Source": "Microsoft-style · Table plans",
        "Category": "Cost",
        "Title": "Evaluate Basic / Auxiliary plans for low-value verbose logs",
        "Summary": (
            "Verbose operational telemetry that is rarely queried for detections "
            "may belong on a lower-cost plan when retention/query needs allow."
        ),
        "Suggested action": "Use Tier Recommendation column; validate query/SOC requirements first.",
    },
    {
        "Source": "Microsoft-style · Detection coverage",
        "Category": "Security",
        "Title": "Enable analytics content for high-value data sources already ingested",
        "Summary": (
            "Paying for ingest without enabled detections wastes both budget and signal. "
            "Either map rules or reduce ingest."
        ),
        "Suggested action": "Compare Active Analytics Rules vs spend; prefer rule coverage or DCR reduction.",
    },
    {
        "Source": "Complements Optimization Workbook",
        "Category": "Governance",
        "Title": "Use portal workbook for Microsoft visuals; use this engine for priced audits",
        "Summary": (
            "The Sentinel Optimization Workbook provides native portal insight. "
            "This product applies customer $/GB, Ghost-table correlation, and portable reports."
        ),
        "Suggested action": "Export HTML/CSV for FinOps; keep workbook for SOC portal deep-dives.",
    },
]


def suggest_log_tier(table: str, status: str, rules: int, size_gb_day: float) -> str:
    """Advisory table-plan guidance (Analytics vs Basic/Auxiliary). Enhancement #5."""
    if status == STATUS_WASTE and (table in BASIC_OR_AUX_CANDIDATES or size_gb_day >= 10):
        return (
            "Candidate: Basic or Auxiliary Logs (if interactive hunting is rare) "
            "OR keep Analytics + aggressive DCR filter"
        )
    if status == STATUS_UNDERUTILIZED and size_gb_day >= 15:
        return "Keep Analytics for detection fields; move verbose columns/noise to filtered DCR path"
    if rules >= 3:
        return "Retain Analytics plan — active detection dependency"
    return "Retain Analytics unless query patterns prove otherwise"


def detection_risk_note(table: str, status: str, rules: int) -> str:
    """SOC-aware caution when proposing ingest reduction. Enhancement #3."""
    if status == STATUS_WASTE and rules == 0:
        return (
            f"Low immediate detection impact if unused today, but confirm no planned "
            f"hunting/content for '{table}' before filtering. Document change control."
        )
    if status == STATUS_UNDERUTILIZED:
        return (
            f"Only {rules} rule(s) reference this table — tighten filters carefully and "
            "re-test those analytics rules after any DCR change."
        )
    return (
        "Active rule coverage present — prefer column pruning over broad drops; "
        "regression-test detections after changes."
    )


# ---------------------------------------------------------------------------
# 2. Read-only metadata ingestion (demo + Service Principal live)
# ---------------------------------------------------------------------------

@dataclass
class ServicePrincipalConfig:
    """Customer tenant credentials for read-only Azure / Sentinel access."""

    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str
    resource_group: str
    workspace_name: str
    workspace_id: str  # Log Analytics customer/workspace GUID used by Query API

    def validate(self) -> list[str]:
        missing: list[str] = []
        fields = {
            "Tenant ID": self.tenant_id,
            "Client ID": self.client_id,
            "Client Secret": self.client_secret,
            "Subscription ID": self.subscription_id,
            "Resource Group": self.resource_group,
            "Workspace Name": self.workspace_name,
            "Workspace ID (GUID)": self.workspace_id,
        }
        for label, value in fields.items():
            if not str(value or "").strip():
                missing.append(label)
        return missing


def estimate_monthly_cost(
    size_gb_day: float,
    cost_per_gb: float = DEFAULT_COST_PER_GB_USD,
) -> float:
    """Convert daily GB ingest into approximate monthly USD cost using portal pricing."""
    return round(float(size_gb_day) * float(USAGE_LOOKBACK_DAYS) * float(cost_per_gb), 2)


def infer_category(table_name: str) -> str:
    """Best-effort category label for live DataType names."""
    for item in DEMO_TABLE_CATALOGUE:
        if item["Table Name"].lower() == table_name.lower():
            return str(item["Category"])
    lowered = table_name.lower()
    if "sign" in lowered or "aad" in lowered or "auditlog" in lowered:
        return "Identity"
    if "device" in lowered or "mde" in lowered or "securityevent" in lowered:
        return "Endpoint / Security"
    if "syslog" in lowered or "commonsecurity" in lowered or "dns" in lowered:
        return "Network / Firewall"
    if "azure" in lowered or "activity" in lowered:
        return "Azure Control Plane"
    return "Live Workspace"


def build_demo_metadata(cost_per_gb: float = DEFAULT_COST_PER_GB_USD) -> pd.DataFrame:
    """
    Construct a demo metadata frame from the built-in Sentinel table catalogue.
    Costs use the customer-entered (or default) $/GB rate from the portal.
    """
    rows = []
    for item in DEMO_TABLE_CATALOGUE:
        size = float(item["Size_GB_Day"])
        rows.append(
            {
                "Table Name": item["Table Name"],
                "Category": item["Category"],
                "Size GB/Day": size,
                "Monthly Cost (USD)": estimate_monthly_cost(size, cost_per_gb),
                "Active Analytics Rules": int(item["Active Analytics Rules"]),
            }
        )
    return pd.DataFrame(rows)


def acquire_sp_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    scope: str,
    timeout_seconds: int = 30,
) -> str:
    """
    OAuth2 client-credentials token for a Service Principal.

    Official docs category: Microsoft identity platform — client credentials flow.
    """
    url = TOKEN_URL.format(tenant_id=tenant_id.strip())
    data = {
        "client_id": client_id.strip(),
        "client_secret": client_secret,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    response = requests.post(url, data=data, timeout=timeout_seconds)
    if response.status_code >= 400:
        detail = response.text[:500]
        raise RuntimeError(
            f"Service Principal token request failed ({response.status_code}) "
            f"for scope '{scope}'. Check Tenant ID / Client ID / Secret. Detail: {detail}"
        )
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("Token response did not include access_token.")
    return str(token)


def run_log_analytics_query(
    workspace_id: str,
    access_token: str,
    kql: str,
    timeout_seconds: int = 60,
) -> pd.DataFrame:
    """
    Execute a read-only KQL query via the Log Analytics Query API.

    Official docs category: Microsoft Learn — Azure Monitor Query API.
    """
    url = LA_QUERY_URL.format(workspace_id=workspace_id.strip())
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        url,
        headers=headers,
        json={"query": kql},
        timeout=timeout_seconds,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Log Analytics query failed ({response.status_code}): {response.text[:800]}"
        )

    payload = response.json()
    tables = payload.get("tables") or []
    if not tables:
        return pd.DataFrame()

    primary = tables[0]
    columns = [col["name"] for col in primary.get("columns", [])]
    rows = primary.get("rows") or []
    return pd.DataFrame(rows, columns=columns)


def fetch_enabled_analytics_rules(
    sp: ServicePrincipalConfig,
    arm_token: str,
    timeout_seconds: int = 60,
) -> list[dict[str, Any]]:
    """
    List Microsoft Sentinel analytics / alert rules (GET only).

    Official docs category: Microsoft Learn — Sentinel Alert Rules API.
    """
    url = ARM_ALERT_RULES_URL.format(
        subscription_id=sp.subscription_id.strip(),
        resource_group=sp.resource_group.strip(),
        workspace_name=sp.workspace_name.strip(),
    )
    headers = {
        "Authorization": f"Bearer {arm_token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers, timeout=timeout_seconds)
    if response.status_code >= 400:
        raise RuntimeError(
            f"Sentinel alertRules list failed ({response.status_code}): "
            f"{response.text[:800]}"
        )

    payload = response.json()
    return list(payload.get("value") or [])


def count_rules_per_table(
    rules: list[dict[str, Any]],
    table_names: list[str],
) -> dict[str, int]:
    """
    Correlate enabled analytics rules to tables by scanning rule KQL for table names.
    Read-only heuristic — does not modify rules.
    """
    counts = {name: 0 for name in table_names}
    if not table_names:
        return counts

    # Prefer longer names first to reduce partial collisions.
    sorted_names = sorted(table_names, key=len, reverse=True)

    for rule in rules:
        props = rule.get("properties") or {}
        if props.get("enabled", True) is False:
            continue

        query_text = str(props.get("query") or "")
        if not query_text:
            continue

        for table in sorted_names:
            # Word-boundary style match for KQL table identifiers.
            pattern = rf"(?<![A-Za-z0-9_]){re.escape(table)}(?![A-Za-z0-9_])"
            if re.search(pattern, query_text):
                counts[table] = counts.get(table, 0) + 1

    return counts


def fetch_live_workspace_metadata(
    sp: ServicePrincipalConfig,
    cost_per_gb: float,
) -> pd.DataFrame:
    """
    Pull live billable ingest (Usage table) + analytics-rule dependency counts
    from the customer tenant using a Service Principal. No Azure writes.
    """
    missing = sp.validate()
    if missing:
        raise ValueError(
            "Live sync requires: " + ", ".join(missing)
        )

    la_token = acquire_sp_token(
        sp.tenant_id, sp.client_id, sp.client_secret, LA_SCOPE
    )
    usage_df = run_log_analytics_query(sp.workspace_id, la_token, USAGE_KQL)
    if usage_df is None or usage_df.empty:
        raise RuntimeError(
            "Live Usage query returned no billable table rows for the lookback window."
        )

    if "DataType" not in usage_df.columns or "BillableDataGB" not in usage_df.columns:
        raise RuntimeError(
            f"Unexpected Usage query columns: {list(usage_df.columns)}"
        )

    table_names = [str(t) for t in usage_df["DataType"].tolist()]

    rule_counts: dict[str, int] = {name: 0 for name in table_names}
    rules_warning = ""
    try:
        arm_token = acquire_sp_token(
            sp.tenant_id, sp.client_id, sp.client_secret, ARM_SCOPE
        )
        rules = fetch_enabled_analytics_rules(sp, arm_token)
        rule_counts = count_rules_per_table(rules, table_names)
    except Exception as exc:  # noqa: BLE001 — Usage still valuable if rules API denied
        rules_warning = str(exc)
        st.session_state["rules_sync_warning"] = (
            "Usage data loaded, but analytics-rule correlation failed "
            f"(rules defaulted to 0). Detail: {rules_warning}"
        )
    else:
        st.session_state["rules_sync_warning"] = None

    rows = []
    for _, row in usage_df.iterrows():
        table = str(row["DataType"])
        total_gb = float(row["BillableDataGB"])
        size_per_day = round(total_gb / float(USAGE_LOOKBACK_DAYS), 4)
        rows.append(
            {
                "Table Name": table,
                "Category": infer_category(table),
                "Size GB/Day": size_per_day,
                "Monthly Cost (USD)": estimate_monthly_cost(size_per_day, cost_per_gb),
                "Active Analytics Rules": int(rule_counts.get(table, 0)),
            }
        )

    return pd.DataFrame(rows)


def normalize_usage_daily_frame(
    raw_df: pd.DataFrame,
    cost_per_gb: float,
) -> pd.DataFrame:
    """Map live Usage daily query columns → Spikes & Trends schema."""
    if raw_df is None or raw_df.empty:
        return pd.DataFrame(
            columns=[
                "Date",
                "Table Name",
                "Category",
                "GB/Day",
                "Est. Daily Cost (USD)",
            ]
        )

    frame = raw_df.copy()
    # Accept either KQL aliases or already-normalized names
    rename_map = {}
    if "TableName" in frame.columns and "Table Name" not in frame.columns:
        rename_map["TableName"] = "Table Name"
    if "BillableGB" in frame.columns and "GB/Day" not in frame.columns:
        rename_map["BillableGB"] = "GB/Day"
    if "DataType" in frame.columns and "Table Name" not in frame.columns:
        rename_map["DataType"] = "Table Name"
    if rename_map:
        frame = frame.rename(columns=rename_map)

    required = {"Date", "Table Name", "GB/Day"}
    missing = required - set(frame.columns)
    if missing:
        raise RuntimeError(
            f"Daily Usage query missing columns {sorted(missing)}; got {list(frame.columns)}"
        )

    frame["Date"] = pd.to_datetime(frame["Date"], utc=True).dt.tz_localize(None)
    frame["Table Name"] = frame["Table Name"].astype(str)
    frame["GB/Day"] = pd.to_numeric(frame["GB/Day"], errors="coerce").fillna(0.0)
    frame["Category"] = frame["Table Name"].apply(infer_category)
    frame["Est. Daily Cost (USD)"] = (
        frame["GB/Day"].astype(float) * float(cost_per_gb)
    ).round(4)
    return frame[
        ["Date", "Table Name", "Category", "GB/Day", "Est. Daily Cost (USD)"]
    ].sort_values(["Table Name", "Date"]).reset_index(drop=True)


def fetch_live_usage_daily_timeseries(
    sp: ServicePrincipalConfig,
    cost_per_gb: float,
    lookback_days: int = 31,
) -> pd.DataFrame:
    """
    Read-only daily Usage pull for anomaly / cost-creep charts.
    Called during live SP sync; failures should fall back to simulation.
    """
    missing = sp.validate()
    if missing:
        raise ValueError("Live daily Usage requires: " + ", ".join(missing))

    la_token = acquire_sp_token(
        sp.tenant_id, sp.client_id, sp.client_secret, LA_SCOPE
    )
    kql = build_usage_daily_kql(lookback_days)
    raw = run_log_analytics_query(sp.workspace_id, la_token, kql)
    if raw is None or raw.empty:
        raise RuntimeError("Daily Usage KQL returned no rows for the lookback window.")
    return normalize_usage_daily_frame(raw, cost_per_gb)


def resolve_ingest_timeseries(
    audit_df: pd.DataFrame,
    lookback_days: int,
    cost_per_gb: float,
) -> tuple[pd.DataFrame, str]:
    """
    Prefer live daily Usage cached at sync time; otherwise simulate.
    Apply-range filters the cached live series locally (no extra Azure call).
    """
    days = max(1, min(int(lookback_days), 90))
    live = st.session_state.get("live_ingest_timeseries")
    if isinstance(live, pd.DataFrame) and not live.empty:
        live_costed = live.copy()
        live_costed["Est. Daily Cost (USD)"] = (
            live_costed["GB/Day"].astype(float) * float(cost_per_gb)
        ).round(4)
        # Keep tables present in current filtered audit view when possible
        if audit_df is not None and not audit_df.empty and "Table Name" in audit_df.columns:
            keep = set(audit_df["Table Name"].astype(str))
            live_costed = live_costed[live_costed["Table Name"].astype(str).isin(keep)]
        if not live_costed.empty:
            latest = pd.Timestamp(live_costed["Date"].max()).normalize()
            cutoff = latest - pd.Timedelta(days=days - 1)
            windowed = live_costed[live_costed["Date"] >= cutoff].copy()
            if not windowed.empty:
                return (
                    windowed.reset_index(drop=True),
                    f"Live Sentinel Usage daily KQL (window {days}d)",
                )

    simulated = simulate_ingestion_timeseries(
        audit_df,
        lookback_days=days,
        cost_per_gb=cost_per_gb,
    )
    reason = st.session_state.get("timeseries_source") or "Simulation"
    if "Live" in str(reason) and "failed" in str(reason).lower():
        label = reason
    elif st.session_state.get("live_ingest_timeseries") is None:
        label = "Simulation (demo / no live daily Usage cached)"
    else:
        label = "Simulation (live series empty for this window — fallback)"
    return simulated, label


def apply_customer_pricing(df: pd.DataFrame, cost_per_gb: float) -> pd.DataFrame:
    """Recompute Monthly Cost from Size GB/Day using portal $/GB (no Azure call)."""
    if df is None or df.empty:
        return df
    priced = df.copy()
    priced["Monthly Cost (USD)"] = priced["Size GB/Day"].apply(
        lambda size: estimate_monthly_cost(float(size), cost_per_gb)
    )
    return priced


def sync_sentinel_metadata(
    use_live: bool = False,
    sp_config: ServicePrincipalConfig | None = None,
    cost_per_gb: float = DEFAULT_COST_PER_GB_USD,
) -> tuple[pd.DataFrame, str]:
    """
    Orchestrate read-only metadata sync (demo or live SP).

    Returns:
        (dataframe, source_label)
    """
    if use_live:
        if sp_config is None:
            raise ValueError("Live sync selected but Service Principal config is missing.")
        live_df = fetch_live_workspace_metadata(sp_config, cost_per_gb)
        label = (
            f"Live tenant sync via Service Principal "
            f"(workspace '{sp_config.workspace_name}', "
            f"${cost_per_gb:.4f}/GB)"
        )
        return live_df, label

    demo_df = build_demo_metadata(cost_per_gb)
    return (
        demo_df,
        f"Demo catalogue (simulated metadata @ ${cost_per_gb:.4f}/GB)",
    )


# ---------------------------------------------------------------------------
# 3. Correlation engine
# ---------------------------------------------------------------------------

def classify_table(size_gb_day: float, rules_count: int) -> str:
    """
    Flag Ghost / Waste / Underutilized / Active tables.

    Rules (academic, transparent thresholds):
      - Waste / Ghost: 0 analytics rules AND size >= 5 GB/day
      - Underutilized: 1–2 rules AND size >= 15 GB/day
      - Active: everything else with rules > 0, or low-volume unused tables
    """
    if rules_count == 0 and size_gb_day >= 5.0:
        return STATUS_WASTE
    if rules_count == 0:
        return STATUS_WASTE
    if rules_count <= 2 and size_gb_day >= 15.0:
        return STATUS_UNDERUTILIZED
    return STATUS_ACTIVE


def run_correlation_engine(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich metadata with waste status, savings potential, and AI recommendations.
    Pure in-memory transformation — never mutates Azure resources.
    """
    if raw_df is None or raw_df.empty:
        return pd.DataFrame()

    df = raw_df.copy()

    required = {
        "Table Name",
        "Category",
        "Size GB/Day",
        "Monthly Cost (USD)",
        "Active Analytics Rules",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Metadata missing required columns: {sorted(missing)}")

    statuses: list[str] = []
    recommendations: list[str] = []
    kql_filters: list[str] = []
    savings: list[float] = []
    tiers: list[str] = []
    risks: list[str] = []

    for _, row in df.iterrows():
        table = str(row["Table Name"])
        size = float(row["Size GB/Day"])
        cost = float(row["Monthly Cost (USD)"])
        rules = int(row["Active Analytics Rules"])
        status = classify_table(size, rules)
        statuses.append(status)

        if status == STATUS_WASTE:
            tip = KQL_RECOMMENDATIONS.get(table, DEFAULT_RECOMMENDATION)
            # Assume ~70% of waste volume can be filtered via DCR for savings estimate
            savings.append(round(cost * 0.70, 2))
        elif status == STATUS_UNDERUTILIZED:
            tip = UNDERUTILIZED_NOTE
            savings.append(round(cost * 0.35, 2))
        else:
            tip = ACTIVE_TABLE_NOTE
            savings.append(round(cost * 0.10, 2))

        recommendations.append(tip["recommendation"])
        kql_filters.append(tip["kql_filter"])
        tiers.append(suggest_log_tier(table, status, rules, size))
        risks.append(detection_risk_note(table, status, rules))

    df["Status"] = statuses
    df["Projected Monthly Savings (USD)"] = savings
    df["AI Recommendation"] = recommendations
    df["Suggested KQL / DCR Filter"] = kql_filters
    df["Tier Recommendation"] = tiers
    df["Detection Risk Note"] = risks

    # Stable column order for UI + export
    column_order = [
        "Table Name",
        "Category",
        "Size GB/Day",
        "Monthly Cost (USD)",
        "Active Analytics Rules",
        "Status",
        "Projected Monthly Savings (USD)",
        "Tier Recommendation",
        "Detection Risk Note",
        "AI Recommendation",
        "Suggested KQL / DCR Filter",
    ]
    return df[column_order].sort_values(
        by=["Status", "Monthly Cost (USD)"],
        ascending=[True, False],
    ).reset_index(drop=True)


# ---------------------------------------------------------------------------
# 4. Metrics, business case, what-if, history, native recommendations
# ---------------------------------------------------------------------------

def compute_summary_metrics(df: pd.DataFrame) -> dict[str, float]:
    """Derive KPI cards from the (optionally filtered) audit frame."""
    if df is None or df.empty:
        return {
            "total_spend": 0.0,
            "waste_spend": 0.0,
            "projected_savings": 0.0,
            "annual_savings": 0.0,
            "savings_pct": 0.0,
            "ghost_count": 0,
            "table_count": 0,
            "underutilized_count": 0,
            "anomaly_count": 0,
            "elevated_count": 0,
            "creep_count": 0,
        }

    total_spend = float(df["Monthly Cost (USD)"].sum())
    waste_mask = df["Status"] == STATUS_WASTE
    under_mask = df["Status"] == STATUS_UNDERUTILIZED
    waste_spend = float(df.loc[waste_mask, "Monthly Cost (USD)"].sum())
    projected_savings = float(df["Projected Monthly Savings (USD)"].sum())
    savings_pct = round((projected_savings / total_spend) * 100.0, 1) if total_spend else 0.0

    anomaly_count = 0
    elevated_count = 0
    creep_count = 0
    if "Ingestion Anomaly Tag" in df.columns:
        anomaly_count = int((df["Ingestion Anomaly Tag"] == ANOMALY_TAG_SPIKE).sum())
        elevated_count = int((df["Ingestion Anomaly Tag"] == ANOMALY_TAG_ELEVATED).sum())
    if "Cost Creep Flag" in df.columns:
        creep_count = int(df["Cost Creep Flag"].fillna(False).astype(bool).sum())

    return {
        "total_spend": round(total_spend, 2),
        "waste_spend": round(waste_spend, 2),
        "projected_savings": round(projected_savings, 2),
        "annual_savings": round(projected_savings * 12.0, 2),
        "savings_pct": savings_pct,
        "ghost_count": int(waste_mask.sum()),
        "table_count": int(len(df)),
        "underutilized_count": int(under_mask.sum()),
        "anomaly_count": anomaly_count,
        "elevated_count": elevated_count,
        "creep_count": creep_count,
    }


# ---------------------------------------------------------------------------
# 4b. Ingestion Spikes & Trends — Anomaly Detection Engine (MCA viva module)
# ---------------------------------------------------------------------------
#
# Academic note:
#   Live Sentinel workspaces can supply Usage time-series via KQL. For reliable
#   demos (and when only a single-day Size GB/Day snapshot is available), this
#   engine synthesizes a deterministic 30-day history per table, then applies
#   transparent moving-average spike + growth-creep rules. No LLM required.
# ---------------------------------------------------------------------------

def _stable_table_seed(table_name: str) -> int:
    """Deterministic RNG seed from table name (stable across reruns)."""
    digest = hashlib.md5(table_name.encode("utf-8")).hexdigest()
    return int(digest[:8], 16)


def simulate_ingestion_timeseries(
    audit_df: pd.DataFrame,
    lookback_days: int = ANOMALY_LOOKBACK_DAYS,
    cost_per_gb: float = DEFAULT_COST_PER_GB_USD,
) -> pd.DataFrame:
    """
    Build a simulated daily ingest time-series (GB/Day + est. daily cost)
    for each table in the current audit set.

    Pattern mix (deterministic per table):
      - baseline noise around current Size GB/Day
      - optional gradual cost creep
      - optional sudden spike on the latest day (for anomaly demos)
    """
    if audit_df is None or audit_df.empty:
        return pd.DataFrame(
            columns=[
                "Date",
                "Table Name",
                "Category",
                "GB/Day",
                "Est. Daily Cost (USD)",
            ]
        )

    today = datetime.now(timezone.utc).date()
    rows: list[dict[str, Any]] = []

    for _, table_row in audit_df.iterrows():
        table = str(table_row["Table Name"])
        category = str(table_row.get("Category", "Unknown"))
        baseline = max(float(table_row["Size GB/Day"]), 0.05)
        rng = random.Random(_stable_table_seed(table))

        # Assign behavioural profile from seed (stable for viva demos)
        profile_roll = rng.random()
        has_creep = profile_roll > 0.55
        has_spike = profile_roll > 0.72 or table.lower() in {
            "commonsecuritylog",
            "syslog",
            "azurediagnostics",
            "perf",
        }

        creep_factor = rng.uniform(0.004, 0.012) if has_creep else 0.0  # daily growth
        for day_offset in range(lookback_days - 1, -1, -1):
            day = today - timedelta(days=day_offset)
            # Age from start of window (0 = oldest, lookback_days-1 = today)
            age = (lookback_days - 1) - day_offset
            trend = baseline * (1.0 + creep_factor * age)
            noise = rng.uniform(-0.08, 0.08)
            value = max(trend * (1.0 + noise), 0.01)

            # Sudden spike on latest day for selected tables
            if day_offset == 0 and has_spike:
                value *= rng.uniform(1.55, 2.25)

            daily_cost = round(float(value) * float(cost_per_gb), 4)
            rows.append(
                {
                    "Date": pd.Timestamp(day),
                    "Table Name": table,
                    "Category": category,
                    "GB/Day": round(float(value), 4),
                    "Est. Daily Cost (USD)": daily_cost,
                }
            )

    return pd.DataFrame(rows)


def resolve_anomaly_ma_window(lookback_days: int) -> int:
    """
    Adaptive baseline window for short ranges (viva-safe).
      1 day  -> MA window 1 (compare vs single-point baseline / prior day noise)
      2-6    -> window = lookback
      7+     -> classic 7-day MA (capped by lookback)
    """
    days = max(1, int(lookback_days))
    if days <= 1:
        return 1
    if days < ANOMALY_MA_WINDOW:
        return days
    return min(ANOMALY_MA_WINDOW, days)


def detect_ingestion_anomalies(
    timeseries_df: pd.DataFrame,
    ma_window: int = ANOMALY_MA_WINDOW,
    spike_pct: float = ANOMALY_SPIKE_PCT,
    elevated_pct: float = ANOMALY_ELEVATED_PCT,
    creep_pct: float = ANOMALY_CREEP_PCT,
    lookback_days: int = ANOMALY_LOOKBACK_DAYS,
) -> pd.DataFrame:
    """
    Flag sudden spikes vs rolling baseline MA and window cost creep.

    Returns one summary row per table with anomaly tag + growth metrics.
    """
    empty_cols = [
        "Table Name",
        "Category",
        "Today GB/Day",
        "Baseline MA GB/Day",
        "Spike vs MA %",
        "Window Growth %",
        "Ingestion Anomaly Tag",
        "Cost Creep Flag",
        "Anomaly Detail",
    ]
    if timeseries_df is None or timeseries_df.empty:
        return pd.DataFrame(columns=empty_cols)

    ma_window = max(1, int(ma_window))
    min_periods = 1 if ma_window <= 2 else max(2, ma_window // 2)

    summaries: list[dict[str, Any]] = []
    for table, group in timeseries_df.groupby("Table Name"):
        g = group.sort_values("Date").copy()
        g["MA"] = g["GB/Day"].rolling(window=ma_window, min_periods=min_periods).mean()
        today_gb = float(g.iloc[-1]["GB/Day"])
        ma_val = float(g.iloc[-1]["MA"]) if not math.isnan(float(g.iloc[-1]["MA"])) else today_gb
        first_gb = float(g.iloc[0]["GB/Day"])
        growth_pct = ((today_gb - first_gb) / first_gb) if first_gb > 0 else 0.0
        spike_vs_ma = ((today_gb - ma_val) / ma_val) if ma_val > 0 else 0.0
        category = str(g.iloc[-1].get("Category", "Unknown"))

        if spike_vs_ma >= spike_pct:
            tag = ANOMALY_TAG_SPIKE
            detail = (
                f"Today ingest is {spike_vs_ma*100:.1f}% above the "
                f"{ma_window}-day baseline MA — investigate connector storms / misconfig."
            )
        elif spike_vs_ma >= elevated_pct:
            tag = ANOMALY_TAG_ELEVATED
            detail = (
                f"Today ingest is {spike_vs_ma*100:.1f}% above the "
                f"{ma_window}-day baseline MA — monitor for sustained elevation."
            )
        else:
            tag = ANOMALY_TAG_NORMAL
            detail = "Within expected baseline variance versus rolling average."

        # Cost-creep is most meaningful on multi-day windows
        creep_flag = bool(lookback_days >= 7 and growth_pct >= creep_pct)
        if creep_flag:
            detail = (
                detail
                + f" Also shows ~{growth_pct*100:.1f}% growth over the "
                f"{lookback_days}-day window (cost creep)."
            )
        elif lookback_days < 7 and growth_pct >= creep_pct:
            detail = (
                detail
                + f" Short window growth is {growth_pct*100:.1f}% "
                "(cost-creep flag requires ≥7 days)."
            )

        summaries.append(
            {
                "Table Name": str(table),
                "Category": category,
                "Today GB/Day": round(today_gb, 3),
                "Baseline MA GB/Day": round(ma_val, 3),
                "Spike vs MA %": round(spike_vs_ma * 100.0, 1),
                "Window Growth %": round(growth_pct * 100.0, 1),
                "Ingestion Anomaly Tag": tag,
                "Cost Creep Flag": bool(creep_flag),
                "Anomaly Detail": detail,
            }
        )

    result = pd.DataFrame(summaries)
    # Spikes first, then elevated, then by spike magnitude
    tag_rank = {
        ANOMALY_TAG_SPIKE: 0,
        ANOMALY_TAG_ELEVATED: 1,
        ANOMALY_TAG_NORMAL: 2,
    }
    result["_rank"] = result["Ingestion Anomaly Tag"].map(tag_rank)
    return (
        result.sort_values(["_rank", "Spike vs MA %"], ascending=[True, False])
        .drop(columns=["_rank"])
        .reset_index(drop=True)
    )


def enrich_audit_with_anomalies(
    audit_df: pd.DataFrame,
    anomaly_summary: pd.DataFrame,
) -> pd.DataFrame:
    """Merge anomaly tags into the filtered audit frame for UI + exports."""
    if audit_df is None or audit_df.empty:
        return audit_df
    enriched = audit_df.copy()
    # Drop prior anomaly columns so re-apply with a new window stays clean
    drop_cols = [
        "Ingestion Anomaly Tag",
        "Spike vs MA %",
        "Window Growth %",
        "30-Day Growth %",
        "Cost Creep Flag",
        "Anomaly Detail",
        "Baseline MA GB/Day",
        "7-Day MA GB/Day",
    ]
    enriched = enriched.drop(columns=[c for c in drop_cols if c in enriched.columns])

    if anomaly_summary is None or anomaly_summary.empty:
        enriched["Ingestion Anomaly Tag"] = ANOMALY_TAG_NORMAL
        enriched["Spike vs MA %"] = 0.0
        enriched["Window Growth %"] = 0.0
        enriched["Cost Creep Flag"] = False
        return enriched

    merge_cols = [
        "Table Name",
        "Ingestion Anomaly Tag",
        "Spike vs MA %",
        "Window Growth %",
        "Cost Creep Flag",
        "Anomaly Detail",
        "Baseline MA GB/Day",
    ]
    available = [c for c in merge_cols if c in anomaly_summary.columns]
    enriched = enriched.merge(
        anomaly_summary[available],
        on="Table Name",
        how="left",
    )
    enriched["Ingestion Anomaly Tag"] = enriched["Ingestion Anomaly Tag"].fillna(
        ANOMALY_TAG_NORMAL
    )
    enriched["Spike vs MA %"] = enriched["Spike vs MA %"].fillna(0.0)
    enriched["Window Growth %"] = enriched["Window Growth %"].fillna(0.0)
    enriched["Cost Creep Flag"] = enriched["Cost Creep Flag"].fillna(False)
    return enriched


def build_baseline_vs_today_chart(anomaly_summary: pd.DataFrame) -> go.Figure:
    """Grouped bars: today GB/Day vs baseline MA for visual spike comparison."""
    if anomaly_summary is None or anomaly_summary.empty:
        fig = go.Figure()
        fig.update_layout(title="No anomaly data for baseline comparison")
        return fig

    view = anomaly_summary.sort_values("Spike vs MA %", ascending=False).head(10)
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            name="Today GB/Day",
            x=view["Table Name"],
            y=view["Today GB/Day"],
            marker_color="#C62828",
        )
    )
    fig.add_trace(
        go.Bar(
            name="Baseline MA GB/Day",
            x=view["Table Name"],
            y=view["Baseline MA GB/Day"],
            marker_color="#0B3D91",
            opacity=0.75,
        )
    )
    fig.update_layout(
        barmode="group",
        title="Today vs baseline moving average (top movers)",
        yaxis_title="GB/Day",
        xaxis_tickangle=-30,
        height=380,
        margin=dict(l=40, r=20, t=50, b=100),
        plot_bgcolor="#FAFBFC",
        paper_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
    )
    return fig


def build_cost_creep_chart(
    timeseries_df: pd.DataFrame,
    top_n: int = 8,
) -> go.Figure:
    """
    Plotly line chart: last-N-day ingest (GB/Day) for highest-growth / highest-volume tables.
    Helps FinOps spot silent cost increases.
    """
    if timeseries_df is None or timeseries_df.empty:
        fig = go.Figure()
        fig.update_layout(title="No time-series data for cost creep chart")
        return fig

    # Prefer tables with strongest 30-day growth; fall back to volume leaders
    latest = timeseries_df.sort_values("Date").groupby("Table Name").tail(1)
    first = timeseries_df.sort_values("Date").groupby("Table Name").head(1)
    growth = latest[["Table Name", "GB/Day"]].merge(
        first[["Table Name", "GB/Day"]],
        on="Table Name",
        suffixes=("_today", "_start"),
    )
    growth["growth"] = (growth["GB/Day_today"] - growth["GB/Day_start"]) / growth[
        "GB/Day_start"
    ].clip(lower=0.01)
    focus_tables = (
        growth.sort_values("growth", ascending=False)
        .head(top_n)["Table Name"]
        .tolist()
    )
    if not focus_tables:
        focus_tables = (
            timeseries_df.groupby("Table Name")["GB/Day"]
            .mean()
            .sort_values(ascending=False)
            .head(top_n)
            .index.tolist()
        )

    plot_df = timeseries_df[timeseries_df["Table Name"].isin(focus_tables)].copy()
    fig = px.line(
        plot_df,
        x="Date",
        y="GB/Day",
        color="Table Name",
        title="Cost creep & growth trend · daily ingest (GB/Day) over lookback window",
        markers=True,
    )
    fig.update_layout(
        height=460,
        margin=dict(l=40, r=20, t=60, b=40),
        legend_title="Table",
        plot_bgcolor="#FAFBFC",
        paper_bgcolor="rgba(0,0,0,0)",
        hovermode="x unified",
    )
    fig.update_yaxes(title_text="Ingest GB/Day")
    return fig


def build_anomaly_spike_bar(anomaly_summary: pd.DataFrame) -> go.Figure:
    """Bar chart of spike % vs 7-day MA for non-normal tables."""
    if anomaly_summary is None or anomaly_summary.empty:
        fig = go.Figure()
        fig.update_layout(title="No anomaly rows")
        return fig

    focus = anomaly_summary[
        anomaly_summary["Ingestion Anomaly Tag"] != ANOMALY_TAG_NORMAL
    ].copy()
    if focus.empty:
        focus = anomaly_summary.head(8).copy()

    color_map = {
        ANOMALY_TAG_SPIKE: "#C62828",
        ANOMALY_TAG_ELEVATED: "#EF6C00",
        ANOMALY_TAG_NORMAL: "#2E7D32",
    }
    colors = [color_map.get(str(t), "#0B3D91") for t in focus["Ingestion Anomaly Tag"]]
    fig = go.Figure(
        go.Bar(
            x=focus["Table Name"],
            y=focus["Spike vs MA %"],
            marker_color=colors,
            hovertemplate=(
                "<b>%{x}</b><br>Spike vs 7-day MA: %{y:.1f}%"
                "<extra></extra>"
            ),
        )
    )
    fig.add_hline(
        y=ANOMALY_SPIKE_PCT * 100,
        line_dash="dash",
        line_color="#C62828",
        annotation_text="Spike threshold (50%)",
    )
    fig.update_layout(
        title="Sudden volume spikes vs 7-day moving average",
        yaxis_title="Spike vs MA (%)",
        xaxis_tickangle=-30,
        height=380,
        margin=dict(l=40, r=20, t=50, b=100),
        plot_bgcolor="#FAFBFC",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def top_waste_tables(df: pd.DataFrame, n: int = 5) -> pd.DataFrame:
    """Business case: top waste tables by monthly cost. Enhancement #1."""
    if df is None or df.empty:
        return pd.DataFrame()
    waste = df[df["Status"] == STATUS_WASTE].copy()
    if waste.empty:
        waste = df.copy()
    cols = [
        "Table Name",
        "Category",
        "Status",
        "Size GB/Day",
        "Monthly Cost (USD)",
        "Projected Monthly Savings (USD)",
        "Active Analytics Rules",
    ]
    available = [c for c in cols if c in waste.columns]
    return (
        waste.sort_values("Monthly Cost (USD)", ascending=False)
        .head(n)[available]
        .reset_index(drop=True)
    )


def build_roi_blurb(metrics: dict[str, float], cost_per_gb: float) -> str:
    """One-paragraph FinOps ROI narrative. Enhancement #1."""
    return (
        f"At ${cost_per_gb:.4f}/GB, current monthly ingest spend is "
        f"${metrics['total_spend']:,.2f}, of which ${metrics['waste_spend']:,.2f} "
        f"is Ghost/Waste. If recommended DCR filters are applied on prioritized tables, "
        f"estimated savings are ${metrics['projected_savings']:,.2f}/month "
        f"(${metrics['annual_savings']:,.2f}/year) — about {metrics['savings_pct']:.1f}% "
        f"of the audited spend. Validate detection risk notes before change control."
    )


def build_executive_bullets(
    metrics: dict[str, float],
    cost_per_gb: float,
    source_label: str,
    top_df: pd.DataFrame,
) -> list[str]:
    """Deterministic executive summary bullets (no LLM). Enhancement #6."""
    top_names = ", ".join(top_df["Table Name"].head(3).astype(str).tolist()) if not top_df.empty else "n/a"
    return [
        f"Pricing basis: ${cost_per_gb:.4f}/GB · Source: {source_label}",
        f"Monthly spend ${metrics['total_spend']:,.2f} across {metrics['table_count']} tables; "
        f"Ghost/Waste tables: {metrics['ghost_count']}.",
        f"Projected monthly savings ${metrics['projected_savings']:,.2f} "
        f"(~{metrics['savings_pct']:.1f}%); annualized ${metrics['annual_savings']:,.2f}.",
        f"Priority offenders (by cost): {top_names}.",
        "Recommended first action: apply DCR/KQL filters on Ghost tables, "
        "re-test detections, then re-audit with the same $/GB rate.",
    ]


def simulate_what_if(
    df: pd.DataFrame,
    filter_effectiveness_pct: float,
) -> dict[str, float]:
    """
    Before/after simulation on Waste (+ partial Underutilized) tables.
    Enhancement #2 — pure in-memory; no Azure calls.
    """
    base = compute_summary_metrics(df)
    if df is None or df.empty:
        return {
            **base,
            "after_spend": 0.0,
            "simulated_monthly_savings": 0.0,
            "simulated_annual_savings": 0.0,
            "effectiveness": float(filter_effectiveness_pct),
        }

    eff = max(0.0, min(100.0, float(filter_effectiveness_pct))) / 100.0
    after_spend = 0.0
    for _, row in df.iterrows():
        cost = float(row["Monthly Cost (USD)"])
        status = str(row["Status"])
        if status == STATUS_WASTE:
            after_spend += cost * (1.0 - eff)
        elif status == STATUS_UNDERUTILIZED:
            after_spend += cost * (1.0 - (eff * 0.5))
        else:
            after_spend += cost * (1.0 - (eff * 0.05))

    after_spend = round(after_spend, 2)
    simulated = round(base["total_spend"] - after_spend, 2)
    return {
        **base,
        "after_spend": after_spend,
        "simulated_monthly_savings": simulated,
        "simulated_annual_savings": round(simulated * 12.0, 2),
        "effectiveness": float(filter_effectiveness_pct),
    }


def load_audit_history() -> list[dict[str, Any]]:
    """Load persisted governance snapshots. Enhancement #7."""
    try:
        if not HISTORY_PATH.exists():
            return []
        payload = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return payload
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    return []


def append_audit_history(metrics: dict[str, float], cost_per_gb: float, source_label: str) -> None:
    """Append a sync snapshot for trend charts. Enhancement #7."""
    snapshots = load_audit_history()
    snapshots.append(
        {
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "cost_per_gb": float(cost_per_gb),
            "total_spend": float(metrics.get("total_spend", 0)),
            "waste_spend": float(metrics.get("waste_spend", 0)),
            "projected_savings": float(metrics.get("projected_savings", 0)),
            "ghost_count": int(metrics.get("ghost_count", 0)),
            "table_count": int(metrics.get("table_count", 0)),
            "source_label": source_label,
        }
    )
    snapshots = snapshots[-HISTORY_MAX_SNAPSHOTS:]
    try:
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        HISTORY_PATH.write_text(json.dumps(snapshots, indent=2), encoding="utf-8")
    except OSError:
        # Container read-only edge case — keep in session only.
        pass
    st.session_state["audit_history"] = snapshots


def history_dataframe() -> pd.DataFrame:
    snaps = st.session_state.get("audit_history")
    if not snaps:
        snaps = load_audit_history()
        st.session_state["audit_history"] = snaps
    if not snaps:
        return pd.DataFrame()
    return pd.DataFrame(snaps)


def fetch_advisor_cost_recommendations(
    sp: ServicePrincipalConfig,
    timeout_seconds: int = 45,
) -> list[dict[str, str]]:
    """
    Optional live Azure Advisor Cost recommendations (GET only). Enhancement #4.
    Falls back to empty list on failure — UI then shows demo native advisories.
    """
    try:
        token = acquire_sp_token(sp.tenant_id, sp.client_id, sp.client_secret, ARM_SCOPE)
        url = ARM_ADVISOR_URL.format(subscription_id=sp.subscription_id.strip())
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=timeout_seconds,
        )
        if response.status_code >= 400:
            return []
        values = response.json().get("value") or []
        rows: list[dict[str, str]] = []
        for item in values:
            props = item.get("properties") or {}
            category = str(props.get("category") or "")
            # Prefer Cost; accept Security for SOC complementarity.
            if category and category.lower() not in {"cost", "security"}:
                continue
            short = props.get("shortDescription") or {}
            rows.append(
                {
                    "Source": "Azure Advisor (live)",
                    "Category": category or "Cost",
                    "Title": str(short.get("problem") or props.get("impact") or "Advisor recommendation"),
                    "Summary": str(short.get("solution") or props.get("description") or "See Azure Portal Advisor."),
                    "Suggested action": "Review in Azure Advisor; cross-check Ghost tables in this engine before changes.",
                }
            )
            if len(rows) >= 15:
                break
        return rows
    except Exception:  # noqa: BLE001
        return []


def get_native_recommendations_frame() -> pd.DataFrame:
    """Merge live Advisor rows (if any) with built-in Microsoft-style advisories."""
    live = st.session_state.get("native_recommendations_live") or []
    rows = list(live) + list(DEMO_NATIVE_RECOMMENDATIONS)
    return pd.DataFrame(rows)


def apply_sidebar_filters(
    df: pd.DataFrame,
    categories: list[str],
    min_cost: float,
    statuses: list[str],
) -> pd.DataFrame:
    """Apply category / cost / status filters from the sidebar."""
    if df is None or df.empty:
        return df

    filtered = df.copy()
    if categories:
        filtered = filtered[filtered["Category"].isin(categories)]
    if statuses:
        filtered = filtered[filtered["Status"].isin(statuses)]
    filtered = filtered[filtered["Monthly Cost (USD)"] >= float(min_cost)]
    return filtered.reset_index(drop=True)


# ---------------------------------------------------------------------------
# 5. Plotly visualization builders
# ---------------------------------------------------------------------------

def build_cost_waste_chart(df: pd.DataFrame) -> go.Figure:
    """Grouped bar chart: table size vs monthly cost, coloured by waste status."""
    if df is None or df.empty:
        fig = go.Figure()
        fig.update_layout(title="No data available for chart")
        return fig

    chart_df = df.copy()
    color_map = {
        STATUS_WASTE: "#C62828",
        STATUS_UNDERUTILIZED: "#EF6C00",
        STATUS_ACTIVE: "#2E7D32",
    }

    # Dual grouped bars: ingest volume + monthly cost, coloured by correlation status
    fig = go.Figure()
    for status, color in color_map.items():
        subset = chart_df[chart_df["Status"] == status]
        if subset.empty:
            continue
        fig.add_trace(
            go.Bar(
                name=f"{status} · Size GB/Day",
                x=subset["Table Name"],
                y=subset["Size GB/Day"],
                marker_color=color,
                opacity=0.85,
                customdata=subset[
                    ["Category", "Active Analytics Rules", "Projected Monthly Savings (USD)"]
                ],
                hovertemplate=(
                    "<b>%{x}</b><br>Size: %{y:.2f} GB/Day"
                    "<br>Category: %{customdata[0]}"
                    "<br>Rules: %{customdata[1]}"
                    "<br>Est. savings: $%{customdata[2]:,.2f}"
                    "<br>Status: " + status + "<extra></extra>"
                ),
            )
        )
        fig.add_trace(
            go.Bar(
                name=f"{status} · Cost USD",
                x=subset["Table Name"],
                y=subset["Monthly Cost (USD)"],
                marker_color=color,
                opacity=0.45,
                customdata=subset[
                    ["Category", "Active Analytics Rules", "Projected Monthly Savings (USD)"]
                ],
                hovertemplate=(
                    "<b>%{x}</b><br>Monthly Cost: $%{y:,.2f}"
                    "<br>Category: %{customdata[0]}"
                    "<br>Rules: %{customdata[1]}"
                    "<br>Est. savings: $%{customdata[2]:,.2f}"
                    "<br>Status: " + status + "<extra></extra>"
                ),
            )
        )

    fig.update_layout(
        barmode="group",
        title="Table Ingest Volume vs Monthly Cost (Waste Highlighted)",
        xaxis_title="Sentinel / Log Analytics Table",
        yaxis_title="GB/Day  |  Monthly Cost (USD)",
        legend_title="Series",
        height=480,
        margin=dict(l=40, r=20, t=60, b=120),
        xaxis_tickangle=-35,
        plot_bgcolor="#FAFBFC",
        paper_bgcolor="#FFFFFF",
    )
    return fig


def build_waste_pie_chart(df: pd.DataFrame) -> go.Figure:
    """Pie chart of monthly cost distribution by correlation status."""
    if df is None or df.empty:
        fig = go.Figure()
        fig.update_layout(title="No data available for distribution chart")
        return fig

    grouped = (
        df.groupby("Status", as_index=False)["Monthly Cost (USD)"]
        .sum()
        .rename(columns={"Monthly Cost (USD)": "Cost"})
    )
    color_map = {
        STATUS_WASTE: "#C62828",
        STATUS_UNDERUTILIZED: "#EF6C00",
        STATUS_ACTIVE: "#2E7D32",
    }
    fig = px.pie(
        grouped,
        names="Status",
        values="Cost",
        color="Status",
        color_discrete_map=color_map,
        title="Monthly Cost Distribution by Status",
        hole=0.45,
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    fig.update_layout(
        height=420,
        margin=dict(l=20, r=20, t=60, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def build_cost_treemap(df: pd.DataFrame) -> go.Figure:
    """Interactive treemap of monthly cost by status → table."""
    if df is None or df.empty:
        fig = go.Figure()
        fig.update_layout(title="No data for treemap")
        return fig

    plot_df = df.copy()
    plot_df["Root"] = "Sentinel ingest cost"
    fig = px.treemap(
        plot_df,
        path=["Root", "Status", "Table Name"],
        values="Monthly Cost (USD)",
        color="Status",
        color_discrete_map={
            STATUS_WASTE: "#C62828",
            STATUS_UNDERUTILIZED: "#EF6C00",
            STATUS_ACTIVE: "#2E7D32",
            "Sentinel ingest cost": "#0B3D91",
        },
        hover_data={
            "Size GB/Day": ":.2f",
            "Active Analytics Rules": True,
            "Projected Monthly Savings (USD)": ":.2f",
        },
        title="Interactive cost map · click to zoom into Waste / Active tables",
    )
    fig.update_traces(
        textinfo="label+percent entry",
        hovertemplate=(
            "<b>%{label}</b><br>Cost: $%{value:,.2f}"
            "<br>%{percentRoot:.1%} of total<extra></extra>"
        ),
    )
    fig.update_layout(height=460, margin=dict(l=10, r=10, t=50, b=10))
    return fig


def build_top_cost_bar(df: pd.DataFrame, n: int = 10) -> go.Figure:
    """Horizontal Top-N cost bars for FinOps storytelling."""
    if df is None or df.empty:
        fig = go.Figure()
        fig.update_layout(title="No data for top-cost chart")
        return fig

    top = df.sort_values("Monthly Cost (USD)", ascending=True).tail(n)
    color_map = {
        STATUS_WASTE: "#C62828",
        STATUS_UNDERUTILIZED: "#EF6C00",
        STATUS_ACTIVE: "#2E7D32",
    }
    colors = [color_map.get(str(s), "#0B3D91") for s in top["Status"]]
    fig = go.Figure(
        go.Bar(
            x=top["Monthly Cost (USD)"],
            y=top["Table Name"],
            orientation="h",
            marker_color=colors,
            customdata=top[["Status", "Size GB/Day", "Active Analytics Rules"]],
            hovertemplate=(
                "<b>%{y}</b><br>Cost: $%{x:,.2f}"
                "<br>Status: %{customdata[0]}"
                "<br>GB/Day: %{customdata[1]:.2f}"
                "<br>Rules: %{customdata[2]}<extra></extra>"
            ),
        )
    )
    fig.update_layout(
        title=f"Top {min(n, len(top))} tables by monthly cost",
        xaxis_title="Monthly Cost (USD)",
        yaxis_title="",
        height=420,
        margin=dict(l=20, r=20, t=50, b=40),
        plot_bgcolor="#FAFBFC",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def build_savings_gauge(savings_pct: float) -> go.Figure:
    """Executive gauge for projected savings percentage."""
    value = max(0.0, min(100.0, float(savings_pct)))
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=value,
            number={"suffix": "%", "font": {"size": 36}},
            title={"text": "Projected savings opportunity", "font": {"size": 14}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#0B3D91"},
                "steps": [
                    {"range": [0, 25], "color": "#E8EEF7"},
                    {"range": [25, 50], "color": "#C5D4EB"},
                    {"range": [50, 75], "color": "#7FA3D4"},
                    {"range": [75, 100], "color": "#2A9D8F"},
                ],
                "threshold": {
                    "line": {"color": "#C62828", "width": 3},
                    "thickness": 0.75,
                    "value": value,
                },
            },
        )
    )
    fig.update_layout(
        height=280,
        margin=dict(l=20, r=20, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def build_whatif_comparison_chart(sim: dict[str, float]) -> go.Figure:
    """Interactive before/after spend bars driven by what-if slider."""
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            name="Before",
            x=["Monthly spend"],
            y=[sim.get("total_spend", 0)],
            marker_color="#C62828",
            text=[f"${sim.get('total_spend', 0):,.0f}"],
            textposition="auto",
        )
    )
    fig.add_trace(
        go.Bar(
            name="After (simulated)",
            x=["Monthly spend"],
            y=[sim.get("after_spend", 0)],
            marker_color="#2E7D32",
            text=[f"${sim.get('after_spend', 0):,.0f}"],
            textposition="auto",
        )
    )
    fig.add_trace(
        go.Bar(
            name="Simulated savings",
            x=["Monthly savings"],
            y=[sim.get("simulated_monthly_savings", 0)],
            marker_color="#0B3D91",
            text=[f"${sim.get('simulated_monthly_savings', 0):,.0f}"],
            textposition="auto",
        )
    )
    fig.update_layout(
        barmode="group",
        title=f"What-if at {sim.get('effectiveness', 0):.0f}% DCR effectiveness",
        yaxis_title="USD",
        height=360,
        margin=dict(l=40, r=20, t=50, b=40),
        plot_bgcolor="#FAFBFC",
        paper_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
    )
    return fig


def build_rules_heatmap(df: pd.DataFrame) -> go.Figure:
    """Rule-to-table style heatmap proxy: rules vs monthly cost. Enhancement #8."""
    if df is None or df.empty:
        fig = go.Figure()
        fig.update_layout(title="No data for heatmap")
        return fig

    plot_df = df.copy()
    plot_df["Rules"] = plot_df["Active Analytics Rules"].astype(int)
    fig = px.scatter(
        plot_df,
        x="Active Analytics Rules",
        y="Monthly Cost (USD)",
        size="Size GB/Day",
        color="Status",
        hover_name="Table Name",
        title="Detection Coverage vs Cost (bubble ~ ingest GB/Day)",
        color_discrete_map={
            STATUS_WASTE: "#C62828",
            STATUS_UNDERUTILIZED: "#EF6C00",
            STATUS_ACTIVE: "#2E7D32",
        },
    )
    fig.update_layout(height=420, margin=dict(l=40, r=20, t=60, b=40))
    return fig


def build_history_trend_chart(history_df: pd.DataFrame) -> go.Figure:
    """Governance trend from persisted sync snapshots. Enhancement #7."""
    if history_df is None or history_df.empty:
        fig = go.Figure()
        fig.update_layout(title="No audit history yet — sync at least once to start the trend")
        return fig

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=history_df["timestamp_utc"],
            y=history_df["total_spend"],
            mode="lines+markers",
            name="Total monthly spend",
            line=dict(color="#0b3d91"),
        )
    )
    fig.add_trace(
        go.Scatter(
            x=history_df["timestamp_utc"],
            y=history_df["waste_spend"],
            mode="lines+markers",
            name="Waste spend",
            line=dict(color="#C62828"),
        )
    )
    fig.add_trace(
        go.Scatter(
            x=history_df["timestamp_utc"],
            y=history_df["projected_savings"],
            mode="lines+markers",
            name="Projected savings",
            line=dict(color="#2E7D32"),
        )
    )
    fig.update_layout(
        title="Governance Trend · Spend / Waste / Savings across syncs",
        xaxis_title="Sync timestamp (UTC)",
        yaxis_title="USD",
        height=420,
        margin=dict(l=40, r=20, t=60, b=80),
    )
    return fig


def dataframe_to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Enhancement #9 — CSV export for FinOps."""
    return df.to_csv(index=False).encode("utf-8")


def dataframe_to_excel_bytes(
    df: pd.DataFrame,
    sheet_name: str = "Audit",
    extra_sheets: dict[str, pd.DataFrame] | None = None,
) -> bytes:
    """Enhancement #9 — Excel export (requires openpyxl). Supports anomaly sheet."""
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=(sheet_name[:31] or "Audit"))
        if extra_sheets:
            for name, sheet_df in extra_sheets.items():
                safe = (name or "Sheet")[:31]
                if sheet_df is None:
                    continue
                sheet_df.to_excel(writer, index=False, sheet_name=safe)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# 6. HTML audit report exporter
# ---------------------------------------------------------------------------

def _status_badge_color(status: str) -> str:
    if status == STATUS_WASTE:
        return "#C62828"
    if status == STATUS_UNDERUTILIZED:
        return "#EF6C00"
    return "#2E7D32"


def generate_html_report(
    df: pd.DataFrame,
    metrics: dict[str, float],
    source_label: str,
    cost_per_gb: float = DEFAULT_COST_PER_GB_USD,
) -> str:
    """
    Package the filtered audit table and AI recommendations into a
    professionally styled, self-contained HTML report for download.
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_source = html.escape(source_label)
    safe_rate = f"${float(cost_per_gb):.4f}"

    has_anomaly = df is not None and not df.empty and "Ingestion Anomaly Tag" in df.columns
    col_span = 9 if has_anomaly else 8
    if df is None or df.empty:
        rows_html = (
            f"<tr><td colspan='{col_span}' style='text-align:center;padding:24px;'>"
            "No rows matched the current filters.</td></tr>"
        )
    else:
        row_parts: list[str] = []
        for _, row in df.iterrows():
            badge = _status_badge_color(str(row["Status"]))
            anomaly_cell = ""
            if has_anomaly:
                anomaly_cell = (
                    f"<td>{html.escape(str(row.get('Ingestion Anomaly Tag', ANOMALY_TAG_NORMAL)))}</td>"
                )
            row_parts.append(
                "<tr>"
                f"<td>{html.escape(str(row['Table Name']))}</td>"
                f"<td>{html.escape(str(row['Category']))}</td>"
                f"<td style='text-align:right;'>{float(row['Size GB/Day']):.2f}</td>"
                f"<td style='text-align:right;'>${float(row['Monthly Cost (USD)']):,.2f}</td>"
                f"<td style='text-align:center;'>{int(row['Active Analytics Rules'])}</td>"
                f"<td><span class='badge' style='background:{badge};'>"
                f"{html.escape(str(row['Status']))}</span></td>"
                f"{anomaly_cell}"
                f"<td style='text-align:right;'>"
                f"${float(row['Projected Monthly Savings (USD)']):,.2f}</td>"
                f"<td><div class='rec'>{html.escape(str(row['AI Recommendation']))}</div>"
                f"<pre class='kql'>{html.escape(str(row['Suggested KQL / DCR Filter']))}</pre></td>"
                "</tr>"
            )
        rows_html = "\n".join(row_parts)
    anomaly_header = "<th>Ingestion Anomaly</th>" if has_anomaly else ""

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Sentinel Log Waste Audit Report</title>
  <style>
    :root {{
      --ink: #1a2332;
      --muted: #5c6b7a;
      --line: #d9e2ec;
      --bg: #f5f7fa;
      --card: #ffffff;
      --accent: #0b3d91;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      color: var(--ink);
      background: linear-gradient(180deg, #e8eef7 0%, var(--bg) 220px);
      padding: 32px 24px 48px;
    }}
    .wrap {{ max-width: 1100px; margin: 0 auto; }}
    header {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 20px;
      box-shadow: 0 8px 24px rgba(26, 35, 50, 0.06);
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 1.55rem;
      color: var(--accent);
      letter-spacing: -0.02em;
    }}
    .meta {{ color: var(--muted); font-size: 0.92rem; line-height: 1.5; }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin: 20px 0;
    }}
    .kpi {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px 18px;
    }}
    .kpi .label {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    .kpi .value {{ font-size: 1.45rem; font-weight: 700; margin-top: 6px; color: var(--ink); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: hidden;
      font-size: 0.86rem;
    }}
    th {{
      background: #0b3d91;
      color: #fff;
      text-align: left;
      padding: 12px 10px;
      font-weight: 600;
    }}
    td {{
      padding: 12px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    tr:nth-child(even) td {{ background: #f8fafc; }}
    .badge {{
      display: inline-block;
      color: #fff;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .rec {{ margin-bottom: 8px; line-height: 1.45; }}
    .kql {{
      margin: 0;
      background: #0f172a;
      color: #e2e8f0;
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 0.75rem;
      white-space: pre-wrap;
      overflow-x: auto;
    }}
    footer {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.8rem;
      text-align: center;
    }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      header, .kpi, table {{ box-shadow: none; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>AI-Driven Security Log Waste Reduction &amp; DCR Transformation Engine</h1>
      <div class="meta">
        <div><strong>Report type:</strong> Read-only Sentinel metadata audit</div>
        <div><strong>Metadata source:</strong> {safe_source}</div>
        <div><strong>Customer pricing:</strong> {safe_rate} per GB (portal override)</div>
        <div><strong>Cost formula:</strong> Size GB/Day × {USAGE_LOOKBACK_DAYS} × $/GB</div>
        <div><strong>Generated:</strong> {generated_at}</div>
        <div><strong>Operating model:</strong> No write/update calls to Azure or Microsoft Sentinel</div>
      </div>
    </header>

    <section class="kpis">
      <div class="kpi">
        <div class="label">Total Monthly Spend</div>
        <div class="value">${metrics.get('total_spend', 0):,.2f}</div>
      </div>
      <div class="kpi">
        <div class="label">Total Waste Spend</div>
        <div class="value">${metrics.get('waste_spend', 0):,.2f}</div>
      </div>
      <div class="kpi">
        <div class="label">Projected Savings</div>
        <div class="value">${metrics.get('projected_savings', 0):,.2f}</div>
      </div>
      <div class="kpi">
        <div class="label">Projected Savings %</div>
        <div class="value">{metrics.get('savings_pct', 0):.1f}%</div>
      </div>
      <div class="kpi">
        <div class="label">Projected Annual Savings</div>
        <div class="value">${metrics.get('annual_savings', metrics.get('projected_savings', 0) * 12):,.2f}</div>
      </div>
      <div class="kpi">
        <div class="label">Ghost / Waste Tables</div>
        <div class="value">{int(metrics.get('ghost_count', 0))}</div>
      </div>
      <div class="kpi">
        <div class="label">Tables in Report</div>
        <div class="value">{int(metrics.get('table_count', 0))}</div>
      </div>
      <div class="kpi">
        <div class="label">Ingestion Anomalies</div>
        <div class="value">{int(metrics.get('anomaly_count', 0))}</div>
      </div>
      <div class="kpi">
        <div class="label">Cost Creep Tables</div>
        <div class="value">{int(metrics.get('creep_count', 0))}</div>
      </div>
    </section>

    <table>
      <thead>
        <tr>
          <th>Table</th>
          <th>Category</th>
          <th>GB/Day</th>
          <th>Monthly Cost</th>
          <th>Rules</th>
          <th>Status</th>
          {anomaly_header}
          <th>Savings</th>
          <th>AI Recommendation &amp; KQL / DCR Filter</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>

    <footer>
      MCA Final-Year Project · Read-only metadata ingestion model ·
      Recommendations are advisory and require human change control before DCR deployment.
    </footer>
  </div>
</body>
</html>
"""
    return report


# ---------------------------------------------------------------------------
# 7. Streamlit UI
# ---------------------------------------------------------------------------

def inject_custom_css() -> None:
    """Enterprise dashboard styling — cards, chips, cleaner Streamlit chrome."""
    st.markdown(
        """
        <style>
          .stApp {
            background: radial-gradient(circle at top left, #e8eef8 0%, #f3f6fb 42%, #eef6f4 100%);
          }
          .block-container {
            padding-top: 1rem;
            padding-bottom: 2rem;
            max-width: 1280px;
          }
          /* Hide menu/footer only — keep header so sidebar << / >> toggle stays usable */
          #MainMenu {visibility: hidden;}
          footer {visibility: hidden;}
          [data-testid="stToolbar"] {right: 1rem;}
          div[data-testid="stMetric"] {
            background: linear-gradient(180deg, #ffffff 0%, #f7faff 100%);
            border: 1px solid #d5deea;
            border-radius: 14px;
            padding: 14px 16px;
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
          }
          div[data-testid="stMetric"] label { color: #5c6b7a !important; }
          div[data-testid="stTabs"] button[data-baseweb="tab"] {
            font-weight: 600;
          }
          .hero-banner {
            background: linear-gradient(125deg, #071a3a 0%, #0b3d91 48%, #1b6ca8 72%, #2a9d8f 100%);
            color: #fff;
            padding: 26px 28px;
            border-radius: 18px;
            margin-bottom: 1.1rem;
            box-shadow: 0 16px 40px rgba(11, 61, 145, 0.28);
            position: relative;
            overflow: hidden;
          }
          .hero-banner::after {
            content: "";
            position: absolute;
            right: -40px;
            top: -40px;
            width: 180px;
            height: 180px;
            border-radius: 50%;
            background: rgba(255,255,255,0.08);
          }
          .hero-banner h1 {
            margin: 0;
            font-size: 1.55rem;
            font-weight: 750;
            letter-spacing: -0.03em;
            position: relative;
            z-index: 1;
          }
          .hero-banner p {
            margin: 10px 0 0;
            opacity: 0.93;
            font-size: 0.98rem;
            max-width: 820px;
            position: relative;
            z-index: 1;
          }
          .chip-row { margin-top: 14px; position: relative; z-index: 1; }
          .readonly-chip, .mode-chip {
            display: inline-block;
            margin-right: 8px;
            margin-top: 4px;
            background: rgba(255,255,255,0.16);
            border: 1px solid rgba(255,255,255,0.34);
            padding: 5px 12px;
            border-radius: 999px;
            font-size: 0.76rem;
            font-weight: 650;
          }
          .kpi-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
            margin: 0.4rem 0 0.8rem;
          }
          .kpi-card {
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid #d7e0ec;
            border-radius: 16px;
            padding: 14px 16px;
            box-shadow: 0 10px 28px rgba(15, 23, 42, 0.05);
            min-height: 96px;
          }
          .kpi-card .kpi-label {
            color: #5c6b7a;
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            font-weight: 700;
          }
          .kpi-card .kpi-value {
            margin-top: 8px;
            font-size: 1.35rem;
            font-weight: 780;
            color: #12233f;
            letter-spacing: -0.02em;
          }
          .kpi-card.accent-waste { border-top: 3px solid #C62828; }
          .kpi-card.accent-save { border-top: 3px solid #2E7D32; }
          .kpi-card.accent-info { border-top: 3px solid #0B3D91; }
          .panel-card {
            background: rgba(255,255,255,0.88);
            border: 1px solid #d9e2ec;
            border-radius: 16px;
            padding: 16px 18px;
            margin-bottom: 0.85rem;
            box-shadow: 0 10px 26px rgba(15, 23, 42, 0.04);
          }
          .panel-title {
            font-size: 1.05rem;
            font-weight: 720;
            color: #12233f;
            margin: 0 0 6px;
          }
          .panel-sub {
            color: #5c6b7a;
            font-size: 0.86rem;
            margin-bottom: 10px;
          }
          .status-pill {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 700;
            color: #fff;
          }
          .pill-waste { background: #C62828; }
          .pill-under { background: #EF6C00; }
          .pill-active { background: #2E7D32; }
          @media (max-width: 1100px) {
            .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
          }
          @media (max-width: 700px) {
            .kpi-grid { grid-template-columns: 1fr; }
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero(assessment_mode: str = MODE_FULL, cost_per_gb: float = DEFAULT_COST_PER_GB_USD) -> None:
    st.markdown(
        f"""
        <div class="hero-banner">
          <h1>{APP_TITLE}</h1>
          <p>{APP_SUBTITLE}</p>
          <div class="chip-row">
            <span class="readonly-chip">🔒 Read-only metadata</span>
            <span class="mode-chip">👤 {html.escape(str(st.session_state.get('auth_role', 'viewer')))}</span>
            <span class="mode-chip">🎛 {html.escape(assessment_mode)}</span>
            <span class="mode-chip">💵 ${float(cost_per_gb):.4f}/GB</span>
            <span class="mode-chip">📊 Interactive cost governance</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def init_session_state() -> None:
    """Ensure session keys exist so the UI is resilient across reruns."""
    defaults: dict[str, Any] = {
        "audit_df": None,
        "volume_df": None,  # size + rules only; costs reapplied when $/GB changes
        "source_label": "Not synced yet",
        "last_sync_utc": None,
        "last_sync_epoch": None,
        "sync_error": None,
        "rules_sync_warning": None,
        "applied_cost_per_gb": DEFAULT_COST_PER_GB_USD,
        "portal_cost_per_gb": DEFAULT_COST_PER_GB_USD,
        "assessment_mode": MODE_FULL,
        "audit_history": load_audit_history(),
        "native_recommendations_live": [],
        "authenticated": False,
        "auth_user": None,
        "auth_role": None,
        "auth_display_name": None,
        "auth_error": None,
        "sync_frequency": SYNC_FREQ_MANUAL,
        "auto_sync_use_live": False,
        "filter_min_monthly_cost": 0.0,
        "anomaly_lookback_days": ANOMALY_LOOKBACK_DAYS,
        "anomaly_range_preset": ANOMALY_RANGE_1M,
        "anomaly_custom_days": 30,
        "live_ingest_timeseries": None,
        "timeseries_source": "Simulation (not synced yet)",
        "timeseries_sync_warning": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def current_role() -> str | None:
    return st.session_state.get("auth_role")


def is_admin() -> bool:
    return current_role() == ROLE_ADMIN


def is_authenticated() -> bool:
    return bool(st.session_state.get("authenticated"))


def attempt_login(username: str, password: str) -> bool:
    """Validate against hardcoded demo users."""
    key = (username or "").strip().lower()
    user = HARDCODED_USERS.get(key)
    if user is None or user["password"] != password:
        st.session_state["auth_error"] = "Invalid username or password."
        st.session_state["authenticated"] = False
        return False
    st.session_state["authenticated"] = True
    st.session_state["auth_user"] = key
    st.session_state["auth_role"] = user["role"]
    st.session_state["auth_display_name"] = user["display_name"]
    st.session_state["auth_error"] = None
    return True


def logout_user() -> None:
    st.session_state["authenticated"] = False
    st.session_state["auth_user"] = None
    st.session_state["auth_role"] = None
    st.session_state["auth_display_name"] = None
    st.session_state["auth_error"] = None


def render_login_page() -> None:
    """Hardcoded sign-in gate (admin vs viewer). Credentials are not shown on-screen."""
    st.markdown(
        """
        <div class="panel-card">
          <div class="panel-title">Sign in to Sentinel Cost Governance Engine</div>
          <div class="panel-sub">
            Authorized access only.
            <b>Admin</b> can configure Service Principal, pricing, and sync frequency.
            <b>Viewer</b> can explore dashboards and exports only.
            Account details are maintained in <b>BUILD_GUIDE.md</b> (not displayed here).
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    _, center, _ = st.columns((0.7, 1.2, 0.7))
    with center:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
            if submitted:
                if attempt_login(username, password):
                    st.rerun()
        if st.session_state.get("auth_error"):
            st.error(st.session_state["auth_error"])


def maybe_auto_sync(cost_per_gb: float) -> None:
    """
    Lightweight schedule check on page load (admin-configured frequency).
    Uses last_sync_epoch; does not require a separate worker for MCA demos.
    """
    if not is_admin():
        return
    freq = st.session_state.get("sync_frequency", SYNC_FREQ_MANUAL)
    interval = SYNC_FREQ_SECONDS.get(freq)
    if interval is None:
        return
    last_epoch = st.session_state.get("last_sync_epoch")
    now = datetime.now(timezone.utc).timestamp()
    if last_epoch is not None and (now - float(last_epoch)) < float(interval):
        return
    # Auto-run demo sync by default; live only if admin enabled that preference.
    use_live = bool(st.session_state.get("auto_sync_use_live", False))
    sp = st.session_state.get("saved_sp_config")
    if use_live and not isinstance(sp, ServicePrincipalConfig):
        return
    with st.spinner(f"Scheduled sync ({freq}) running..."):
        perform_sync(use_live, sp if use_live else None, float(cost_per_gb))


def perform_sync(
    use_live: bool,
    sp_config: ServicePrincipalConfig | None,
    cost_per_gb: float,
) -> None:
    """Run metadata sync + correlation with presentation-safe error handling."""
    try:
        raw_df, source_label = sync_sentinel_metadata(
            use_live=use_live,
            sp_config=sp_config,
            cost_per_gb=cost_per_gb,
        )
        # Persist volume/rules so pricing can be recalculated without re-querying Azure.
        volume_cols = [
            "Table Name",
            "Category",
            "Size GB/Day",
            "Active Analytics Rules",
        ]
        st.session_state["volume_df"] = raw_df[volume_cols].copy()
        priced = apply_customer_pricing(raw_df, cost_per_gb)
        enriched = run_correlation_engine(priced)
        st.session_state["audit_df"] = enriched
        st.session_state["source_label"] = source_label
        st.session_state["applied_cost_per_gb"] = float(cost_per_gb)
        now = datetime.now(timezone.utc)
        st.session_state["last_sync_utc"] = now.strftime("%Y-%m-%d %H:%M:%S UTC")
        st.session_state["last_sync_epoch"] = now.timestamp()
        st.session_state["sync_error"] = None

        # Governance history snapshot (Enhancement #7)
        append_audit_history(
            compute_summary_metrics(enriched),
            cost_per_gb,
            source_label,
        )

        # Optional native Advisor enrichment (Enhancement #4)
        if use_live and sp_config is not None:
            live_recs = fetch_advisor_cost_recommendations(sp_config)
            st.session_state["native_recommendations_live"] = live_recs
        else:
            st.session_state["native_recommendations_live"] = []

        # Live daily Usage for Spikes & Trends (fallback to simulation on failure)
        st.session_state["timeseries_sync_warning"] = None
        if use_live and sp_config is not None:
            try:
                daily_ts = fetch_live_usage_daily_timeseries(
                    sp_config,
                    cost_per_gb=float(cost_per_gb),
                    lookback_days=31,
                )
                st.session_state["live_ingest_timeseries"] = daily_ts
                st.session_state["timeseries_source"] = (
                    "Live Sentinel Usage daily KQL (cached at sync)"
                )
            except Exception as ts_exc:  # noqa: BLE001
                st.session_state["live_ingest_timeseries"] = None
                st.session_state["timeseries_source"] = (
                    f"Simulation (live daily Usage failed: {ts_exc})"
                )
                st.session_state["timeseries_sync_warning"] = (
                    "Table totals synced, but daily Usage time-series query failed. "
                    f"Spikes & Trends will use simulation. Detail: {ts_exc}"
                )
        else:
            st.session_state["live_ingest_timeseries"] = None
            st.session_state["timeseries_source"] = (
                "Simulation (demo catalogue sync)"
            )
    except ValueError as exc:
        st.session_state["sync_error"] = f"Configuration / validation error: {exc}"
    except Exception as exc:  # noqa: BLE001 — keep demo from crashing mid-presentation
        st.session_state["sync_error"] = f"Sync failure: {exc}"


def refresh_pricing(cost_per_gb: float) -> None:
    """Re-apply customer $/GB to cached volumes and re-run correlation (no Azure call)."""
    volume_df = st.session_state.get("volume_df")
    if volume_df is None or volume_df.empty:
        return
    try:
        priced = apply_customer_pricing(volume_df, cost_per_gb)
        enriched = run_correlation_engine(priced)
        st.session_state["audit_df"] = enriched
        st.session_state["applied_cost_per_gb"] = float(cost_per_gb)
        base = str(st.session_state.get("source_label", "Cached volume data"))
        base = re.sub(r"\s*@\s*\$[0-9.]+/GB", "", base)
        base = re.sub(r"\s*\(\$[0-9.]+/GB\)", "", base)
        st.session_state["source_label"] = f"{base.strip()} (${cost_per_gb:.4f}/GB)"
    except Exception as exc:  # noqa: BLE001
        st.session_state["sync_error"] = f"Pricing refresh failed: {exc}"


def render_sidebar(
    df: pd.DataFrame | None,
) -> tuple[list[str], float, list[str], float, str]:
    """Sidebar: role-aware controls, pricing, SP (admin), filters."""
    st.sidebar.markdown(
        f"**Signed in:** {st.session_state.get('auth_display_name', 'User')}  \n"
        f"Role: `{st.session_state.get('auth_role', 'viewer')}` · "
        f"User: `{st.session_state.get('auth_user', '')}`"
    )
    if st.sidebar.button("Sign out", use_container_width=True):
        logout_user()
        st.rerun()

    st.sidebar.caption(
        "Sidebar tip: collapse with ≪, reopen with ≫ in the top header (kept visible)."
    )
    st.sidebar.divider()

    st.sidebar.header("Assessment Mode")
    assessment_mode = st.sidebar.selectbox(
        "Preset view",
        options=ASSESSMENT_MODES,
        help=(
            "Executive: summary + business case. FinOps: cost/tiering. "
            "SOC: coverage risk + heatmap. Full: all panels."
        ),
        key="assessment_mode",
    )

    admin = is_admin()
    if admin:
        st.sidebar.header("Customer Pricing")
        st.sidebar.caption(
            "Enter your Microsoft offer / EA / discounted Analytics ingestion rate. "
            "Formula: Monthly Cost = GB/Day × 30 × $/GB."
        )
        cost_per_gb = st.sidebar.number_input(
            "Cost per GB (USD)",
            min_value=0.0,
            max_value=100.0,
            step=0.01,
            format="%.4f",
            help="Override the default demo rate with your real Microsoft pricing.",
            key="portal_cost_per_gb",
        )
    else:
        cost_per_gb = float(
            st.session_state.get("applied_cost_per_gb")
            or st.session_state.get("portal_cost_per_gb")
            or DEFAULT_COST_PER_GB_USD
        )
        st.sidebar.header("Customer Pricing")
        st.sidebar.info(f"View-only rate: **${cost_per_gb:.4f}/GB** (admin-managed)")

    # If data is loaded and the portal rate changed, reprice without Azure round-trip.
    previous_rate = st.session_state.get("applied_cost_per_gb")
    if (
        admin
        and st.session_state.get("volume_df") is not None
        and previous_rate is not None
        and abs(float(previous_rate) - float(cost_per_gb)) > 1e-9
    ):
        refresh_pricing(float(cost_per_gb))
        df = st.session_state.get("audit_df")

    st.sidebar.divider()
    sp_config: ServicePrincipalConfig | None = st.session_state.get("saved_sp_config")
    use_live = bool(st.session_state.get("auto_sync_use_live", False))

    if admin:
        st.sidebar.header("Workspace Controls (Admin)")
        st.sidebar.caption(
            "Read-only Azure metadata sync. Configure SP and schedule here."
        )

        use_live = st.sidebar.checkbox(
            "Live sync with Service Principal",
            value=bool(st.session_state.get("auto_sync_use_live", False)),
            help=(
                "Authenticate to the customer tenant with App Registration "
                "(Tenant ID, Client ID, Client Secret) and pull Usage + Sentinel rules."
            ),
            key="auto_sync_use_live",
        )

        sync_frequency = st.sidebar.selectbox(
            "Live / demo sync frequency",
            options=SYNC_FREQUENCY_OPTIONS,
            help="Checked on page load. Manual = sync only when you click the button.",
            key="sync_frequency",
        )
        st.sidebar.caption(f"Schedule: **{sync_frequency}**")

        with st.sidebar.expander(
            "Service Principal & Workspace",
            expanded=use_live,
        ):
            saved = st.session_state.get("saved_sp_config")
            tenant_id = st.text_input(
                "Tenant ID",
                value=getattr(saved, "tenant_id", "") if saved else "",
                help="Azure AD directory (tenant) ID",
            )
            client_id = st.text_input(
                "Client ID (App ID)",
                value=getattr(saved, "client_id", "") if saved else "",
            )
            client_secret = st.text_input(
                "Client Secret",
                value=getattr(saved, "client_secret", "") if saved else "",
                type="password",
                help="Session-only. Never commit secrets to source control.",
            )
            subscription_id = st.text_input(
                "Subscription ID",
                value=getattr(saved, "subscription_id", "") if saved else "",
            )
            resource_group = st.text_input(
                "Resource Group",
                value=getattr(saved, "resource_group", "") if saved else "",
            )
            workspace_name = st.text_input(
                "Log Analytics Workspace Name",
                value=getattr(saved, "workspace_name", "") if saved else "",
            )
            workspace_id = st.text_input(
                "Workspace ID (GUID)",
                value=getattr(saved, "workspace_id", "") if saved else "",
                help="Log Analytics workspace customer ID used by the Query API.",
            )
            st.caption(
                "Required SP roles (least privilege): Log Analytics Reader + "
                "Microsoft Sentinel Reader on the workspace."
            )
            sp_config = ServicePrincipalConfig(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                subscription_id=subscription_id,
                resource_group=resource_group,
                workspace_name=workspace_name,
                workspace_id=workspace_id,
            )
            st.session_state["saved_sp_config"] = sp_config

        sync_clicked = st.sidebar.button(
            "🔄 Sync Sentinel Metadata",
            type="primary",
            use_container_width=True,
        )
        if sync_clicked:
            spinner_msg = (
                "Authenticating Service Principal and pulling live Usage / rules..."
                if use_live
                else "Loading demo catalogue with customer $/GB pricing..."
            )
            with st.spinner(spinner_msg):
                perform_sync(use_live, sp_config if use_live else None, float(cost_per_gb))
            if st.session_state.get("sync_error"):
                st.sidebar.error(st.session_state["sync_error"])
            else:
                st.sidebar.success("Metadata sync complete.")
                if st.session_state.get("rules_sync_warning"):
                    st.sidebar.warning(st.session_state["rules_sync_warning"])
                if st.session_state.get("timeseries_sync_warning"):
                    st.sidebar.warning(st.session_state["timeseries_sync_warning"])
                elif use_live and st.session_state.get("live_ingest_timeseries") is not None:
                    st.sidebar.caption("Daily Usage time-series cached for Spikes & Trends.")
    else:
        st.sidebar.header("Workspace Controls")
        st.sidebar.info(
            "Viewer role: dashboards and exports only. "
            "Service Principal, $/GB, and sync schedule are admin-managed."
        )
        if st.session_state.get("last_sync_utc"):
            st.sidebar.caption(f"Last admin sync: {st.session_state['last_sync_utc']}")
        st.sidebar.caption(
            f"Sync schedule: {st.session_state.get('sync_frequency', SYNC_FREQ_MANUAL)}"
        )

    st.sidebar.divider()
    st.sidebar.header("Audit Filters")

    # Refresh local reference after possible sync/reprice.
    df = st.session_state.get("audit_df")

    if df is None or df.empty:
        st.sidebar.info("Sync metadata to enable filters.")
        return [], 0.0, [], float(cost_per_gb), str(assessment_mode)

    all_categories = sorted(df["Category"].dropna().unique().tolist())
    all_statuses = sorted(df["Status"].dropna().unique().tolist())
    observed_max_cost = float(df["Monthly Cost (USD)"].max()) if not df.empty else 0.0

    selected_categories = st.sidebar.multiselect(
        "Log category",
        options=all_categories,
        default=all_categories,
    )
    # Free-entry budget threshold (not capped by current table max).
    min_cost = st.sidebar.number_input(
        "Minimum monthly cost (USD)",
        min_value=0.0,
        max_value=10_000_000.0,
        step=100.0,
        format="%.2f",
        help=(
            "Enter your cleanup budget threshold. Only tables with monthly cost "
            "at or above this amount are shown. Not limited to the current dataset max."
        ),
        key="filter_min_monthly_cost",
    )
    st.sidebar.caption(
        f"Hint: highest table cost in current data ≈ **${observed_max_cost:,.2f}**/mo. "
        "Enter any higher/lower budget to focus cleanup."
    )
    selected_statuses = st.sidebar.multiselect(
        "Status (Waste vs Active)",
        options=all_statuses,
        default=all_statuses,
    )

    st.sidebar.divider()
    st.sidebar.caption(f"Metadata source: {st.session_state.get('source_label', '—')}")
    st.sidebar.caption(
        f"Applied rate: ${float(st.session_state.get('applied_cost_per_gb', cost_per_gb)):.4f}/GB"
    )
    if st.session_state.get("last_sync_utc"):
        st.sidebar.caption(f"Last sync: {st.session_state['last_sync_utc']}")

    return (
        selected_categories,
        float(min_cost),
        selected_statuses,
        float(cost_per_gb),
        str(assessment_mode),
    )


def render_metrics(metrics: dict[str, float]) -> None:
    """Rich KPI card strip + waste share progress."""
    waste_share = 0.0
    if metrics.get("total_spend"):
        waste_share = (metrics["waste_spend"] / metrics["total_spend"]) * 100.0

    st.markdown(
        f"""
        <div class="kpi-grid">
          <div class="kpi-card accent-info">
            <div class="kpi-label">Total monthly spend</div>
            <div class="kpi-value">${metrics['total_spend']:,.2f}</div>
          </div>
          <div class="kpi-card accent-waste">
            <div class="kpi-label">Waste / ghost spend</div>
            <div class="kpi-value">${metrics['waste_spend']:,.2f}</div>
          </div>
          <div class="kpi-card accent-save">
            <div class="kpi-label">Projected monthly save</div>
            <div class="kpi-value">${metrics['projected_savings']:,.2f}</div>
          </div>
          <div class="kpi-card accent-save">
            <div class="kpi-label">Projected annual save</div>
            <div class="kpi-value">${metrics.get('annual_savings', 0):,.2f}</div>
          </div>
          <div class="kpi-card accent-info">
            <div class="kpi-label">Savings opportunity</div>
            <div class="kpi-value">{metrics['savings_pct']:.1f}%</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(
        f"Waste share of audited spend: **{waste_share:.1f}%** · "
        f"Ghost tables: **{int(metrics.get('ghost_count', 0))}** · "
        f"Tables in view: **{int(metrics.get('table_count', 0))}** · "
        f"Spikes: **{int(metrics.get('anomaly_count', 0))}** · "
        f"Cost creep: **{int(metrics.get('creep_count', 0))}**"
    )
    st.progress(min(max(waste_share / 100.0, 0.0), 1.0))


def _mode_flags(mode: str) -> dict[str, bool]:
    """Which panels to show for each assessment preset."""
    if mode == MODE_EXEC:
        return {
            "exec": True,
            "business": True,
            "whatif": True,
            "charts": False,
            "heatmap": False,
            "history": True,
            "anomalies": True,
            "native": False,
            "audit": False,
            "export": True,
        }
    if mode == MODE_FINOPS:
        return {
            "exec": False,
            "business": True,
            "whatif": True,
            "charts": True,
            "heatmap": False,
            "history": True,
            "anomalies": True,
            "native": True,
            "audit": True,
            "export": True,
        }
    if mode == MODE_SOC:
        return {
            "exec": False,
            "business": False,
            "whatif": False,
            "charts": True,
            "heatmap": True,
            "history": False,
            "anomalies": True,
            "native": True,
            "audit": True,
            "export": True,
        }
    # Full assessment
    return {
        "exec": True,
        "business": True,
        "whatif": True,
        "charts": True,
        "heatmap": True,
        "history": True,
        "anomalies": True,
        "native": True,
        "audit": True,
        "export": True,
    }


def render_results(
    filtered_df: pd.DataFrame,
    source_label: str,
    cost_per_gb: float,
    assessment_mode: str,
) -> None:
    """Dashboard-first interactive UX: KPIs → charts → tabs for deep dive."""
    flags = _mode_flags(assessment_mode)
    top_df = top_waste_tables(filtered_df, n=5)

    # --- Anomaly / trend engine (live Usage daily KQL if cached, else simulation) ---
    anomaly_lookback = int(
        st.session_state.get("anomaly_lookback_days", ANOMALY_LOOKBACK_DAYS)
    )
    anomaly_lookback = max(1, min(anomaly_lookback, 90))
    anomaly_ma_window = resolve_anomaly_ma_window(anomaly_lookback)
    timeseries_df, timeseries_label = resolve_ingest_timeseries(
        filtered_df,
        lookback_days=anomaly_lookback,
        cost_per_gb=cost_per_gb,
    )
    anomaly_summary = detect_ingestion_anomalies(
        timeseries_df,
        ma_window=anomaly_ma_window,
        lookback_days=anomaly_lookback,
    )
    filtered_df = enrich_audit_with_anomalies(filtered_df, anomaly_summary)
    metrics = compute_summary_metrics(filtered_df)

    # --- Overview strip ---
    render_metrics(metrics)
    st.caption(
        f"Mode: **{assessment_mode}** · Pricing: **${cost_per_gb:.4f}/GB** · "
        f"Formula: Size GB/Day × {USAGE_LOOKBACK_DAYS} × $/GB · Source: {source_label}"
    )

    # --- Interactive command center (always visible when charts/business relevant) ---
    show_overview_charts = flags["charts"] or flags["business"] or flags["exec"] or flags["whatif"]
    if show_overview_charts:
        st.markdown(
            """
            <div class="panel-card">
              <div class="panel-title">Interactive command center</div>
              <div class="panel-sub">
                Explore cost waste visually first — zoom the treemap, hover Top-N bars,
                and read the savings gauge. Tables below support the story.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        left, right = st.columns((1.65, 1.0))
        with left:
            st.plotly_chart(build_cost_treemap(filtered_df), use_container_width=True)
        with right:
            st.plotly_chart(
                build_savings_gauge(metrics.get("savings_pct", 0.0)),
                use_container_width=True,
            )
            st.plotly_chart(build_top_cost_bar(filtered_df, n=8), use_container_width=True)

        if flags["whatif"]:
            st.markdown(
                """
                <div class="panel-card">
                  <div class="panel-title">Live what-if simulator</div>
                  <div class="panel-sub">
                    Drag effectiveness to preview before/after spend interactively.
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            effectiveness = st.slider(
                "Assumed DCR filter effectiveness on Waste tables (%)",
                min_value=0,
                max_value=100,
                value=70,
                step=5,
                help=(
                    "Waste tables reduced by this %; Underutilized by half that rate; "
                    "Active by a small column-pruning factor."
                ),
                key="whatif_effectiveness",
            )
            sim = simulate_what_if(filtered_df, float(effectiveness))
            w1, w2, w3, w4 = st.columns(4)
            w1.metric("Before (monthly)", f"${sim['total_spend']:,.2f}")
            w2.metric("After (monthly)", f"${sim['after_spend']:,.2f}")
            w3.metric("Simulated monthly save", f"${sim['simulated_monthly_savings']:,.2f}")
            w4.metric("Simulated annual save", f"${sim['simulated_annual_savings']:,.2f}")
            st.plotly_chart(build_whatif_comparison_chart(sim), use_container_width=True)
            st.caption(
                "Simulation is advisory only — review Detection Risk Notes and re-test "
                "analytics rules before production DCR changes."
            )

    # --- Deep-dive tabs ---
    tab_labels: list[str] = []
    if flags["exec"]:
        tab_labels.append("📌 Executive")
    if flags["business"]:
        tab_labels.append("💼 Business case")
    if flags.get("anomalies", False):
        tab_labels.append("📈 Ingestion Spikes & Trends")
    if flags["charts"] or flags["heatmap"]:
        tab_labels.append("📈 Visual analytics")
    if flags["history"]:
        tab_labels.append("📉 Governance trend")
    if flags["native"]:
        tab_labels.append("🛡 Native recommendations")
    if flags["audit"]:
        tab_labels.append("🔍 Audit & remediation")
    if flags["export"]:
        tab_labels.append("📦 Export pack")

    if not tab_labels:
        return

    tabs = st.tabs(tab_labels)
    tab_idx = 0

    if flags["exec"]:
        with tabs[tab_idx]:
            st.markdown("#### Executive summary")
            bullets = build_executive_bullets(
                metrics, cost_per_gb, source_label, top_df
            )
            bullets.append(
                f"Ingestion anomalies ({anomaly_lookback}d window): "
                f"{int(metrics.get('anomaly_count', 0))} sudden spike(s), "
                f"{int(metrics.get('elevated_count', 0))} elevated, "
                f"{int(metrics.get('creep_count', 0))} with cost creep."
            )
            for bullet in bullets:
                st.markdown(f"- {bullet}")
            st.success(build_roi_blurb(metrics, cost_per_gb))
            legend = (
                f'<span class="status-pill pill-waste">{STATUS_WASTE}</span> '
                f'<span class="status-pill pill-under">{STATUS_UNDERUTILIZED}</span> '
                f'<span class="status-pill pill-active">{STATUS_ACTIVE}</span>'
            )
            st.markdown(legend, unsafe_allow_html=True)
        tab_idx += 1

    if flags["business"]:
        with tabs[tab_idx]:
            st.markdown("#### Savings business case")
            b1, b2, b3 = st.columns(3)
            b1.metric("Monthly savings", f"${metrics['projected_savings']:,.2f}")
            b2.metric("Annual savings", f"${metrics['annual_savings']:,.2f}")
            b3.metric("Ghost / Waste tables", f"{metrics['ghost_count']}")
            st.plotly_chart(build_top_cost_bar(top_df if not top_df.empty else filtered_df, n=5), use_container_width=True)
            st.dataframe(top_df, use_container_width=True, hide_index=True)
            st.info(build_roi_blurb(metrics, cost_per_gb))
        tab_idx += 1

    if flags.get("anomalies", False):
        with tabs[tab_idx]:
            st.markdown(
                """
                <div class="panel-card">
                  <div class="panel-title">📈 Ingestion Spikes &amp; Trends (Anomaly Detection)</div>
                  <div class="panel-sub">
                    Choose a view window, click <b>Apply range</b>, then explore spike tags and
                    growth charts. Live sync pulls daily <b>Usage</b> via KQL; demo mode
                    (or a failed daily query) falls back to simulation.
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.session_state.get("timeseries_sync_warning"):
                st.warning(st.session_state["timeseries_sync_warning"])
            st.caption(f"Time-series source: **{timeseries_label}**")

            # ---- Range selector + Apply (injects lookback into anomaly engine) ----
            st.markdown("#### View window")
            c_preset, c_custom, c_apply = st.columns((1.4, 1.0, 0.8))
            with c_preset:
                range_preset = st.radio(
                    "Preset range",
                    options=[
                        ANOMALY_RANGE_1D,
                        ANOMALY_RANGE_1W,
                        ANOMALY_RANGE_1M,
                        ANOMALY_RANGE_CUSTOM,
                    ],
                    horizontal=True,
                    key="anomaly_range_preset",
                    help="1 Day / 1 Week / 1 Month or enter a custom day count.",
                )
            with c_custom:
                custom_days = st.number_input(
                    "Custom days",
                    min_value=1,
                    max_value=90,
                    step=1,
                    key="anomaly_custom_days",
                    disabled=(range_preset != ANOMALY_RANGE_CUSTOM),
                )
            with c_apply:
                st.write("")  # vertical align
                st.write("")
                apply_clicked = st.button(
                    "Apply range",
                    type="primary",
                    use_container_width=True,
                    key="anomaly_apply_range",
                    help="Rebuild spike/trend visuals for the selected window.",
                )

            if apply_clicked:
                if range_preset == ANOMALY_RANGE_CUSTOM:
                    new_days = int(custom_days)
                else:
                    new_days = int(ANOMALY_RANGE_PRESETS.get(range_preset, ANOMALY_LOOKBACK_DAYS))
                st.session_state["anomaly_lookback_days"] = max(1, min(new_days, 90))
                st.rerun()

            active_days = int(
                st.session_state.get("anomaly_lookback_days", ANOMALY_LOOKBACK_DAYS)
            )
            active_ma = resolve_anomaly_ma_window(active_days)
            st.info(
                f"Applied window: **{active_days} day(s)** · "
                f"Baseline MA window: **{active_ma} day(s)** · "
                f"Preset: **{st.session_state.get('anomaly_range_preset', ANOMALY_RANGE_1M)}**"
            )

            a1, a2, a3, a4 = st.columns(4)
            a1.metric("Sudden spikes", f"{int(metrics.get('anomaly_count', 0))}")
            a2.metric("Elevated", f"{int(metrics.get('elevated_count', 0))}")
            a3.metric("Cost creep tables", f"{int(metrics.get('creep_count', 0))}")
            a4.metric("View window", f"{active_days}d")

            st.markdown("#### Sub-section 1 · Sudden volume spikes")
            st.caption(
                f"Tag rules: spike if today > {ANOMALY_SPIKE_PCT*100:.0f}% above "
                f"{active_ma}-day baseline MA · elevated if > {ANOMALY_ELEVATED_PCT*100:.0f}% · "
                "otherwise Normal."
            )
            left_spike, right_spike = st.columns((1.15, 1.0))
            with left_spike:
                st.plotly_chart(
                    build_anomaly_spike_bar(anomaly_summary),
                    use_container_width=True,
                )
            with right_spike:
                st.plotly_chart(
                    build_baseline_vs_today_chart(anomaly_summary),
                    use_container_width=True,
                )

            st.dataframe(
                anomaly_summary,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Today GB/Day": st.column_config.NumberColumn(format="%.3f"),
                    "Baseline MA GB/Day": st.column_config.NumberColumn(format="%.3f"),
                    "Spike vs MA %": st.column_config.NumberColumn(format="%.1f"),
                    "Window Growth %": st.column_config.NumberColumn(format="%.1f"),
                    "Anomaly Detail": st.column_config.TextColumn(width="large"),
                },
            )

            st.markdown("#### Sub-section 2 · Cost creep & growth trend")
            st.caption(
                f"Line chart of daily GB/Day over the last **{active_days}** day(s) "
                f"for the strongest growth tables. Cost-creep flag when window ≥ 7 days "
                f"and growth ≥ {ANOMALY_CREEP_PCT*100:.0f}%."
            )
            st.plotly_chart(
                build_cost_creep_chart(timeseries_df, top_n=8),
                use_container_width=True,
            )
            creep_only = anomaly_summary[anomaly_summary["Cost Creep Flag"] == True]  # noqa: E712
            if active_days < 7:
                st.info(
                    "Cost-creep flagging is most meaningful on ≥ 7-day windows. "
                    "Apply **1 Week** or **1 Month** for FinOps growth monitoring."
                )
            elif creep_only.empty:
                st.success(
                    f"No tables exceed the cost-creep growth threshold in this "
                    f"{active_days}-day window."
                )
            else:
                st.warning(
                    f"{len(creep_only)} table(s) show sustained growth — review connectors "
                    "and retention before the silent cost increase compounds."
                )
                st.dataframe(creep_only, use_container_width=True, hide_index=True)
        tab_idx += 1

    if flags["charts"] or flags["heatmap"]:
        with tabs[tab_idx]:
            if flags["charts"]:
                st.markdown("#### Correlation deep dive")
                left, right = st.columns((1.55, 1.0))
                with left:
                    st.plotly_chart(
                        build_cost_waste_chart(filtered_df), use_container_width=True
                    )
                with right:
                    st.plotly_chart(
                        build_waste_pie_chart(filtered_df), use_container_width=True
                    )
            if flags["heatmap"]:
                st.markdown("#### Detection coverage vs cost")
                st.plotly_chart(build_rules_heatmap(filtered_df), use_container_width=True)
                st.caption(
                    "Bubbles in the high-cost / low-rules region are primary Ghost-table candidates."
                )
        tab_idx += 1

    if flags["history"]:
        with tabs[tab_idx]:
            st.markdown("#### Governance trend")
            hist_df = history_dataframe()
            st.plotly_chart(build_history_trend_chart(hist_df), use_container_width=True)
            if not hist_df.empty:
                st.dataframe(hist_df, use_container_width=True, hide_index=True)
            st.caption(f"History file: `{HISTORY_PATH}` (last {HISTORY_MAX_SNAPSHOTS} syncs).")
        tab_idx += 1

    if flags["native"]:
        with tabs[tab_idx]:
            st.markdown("#### Native Microsoft-style recommendations")
            st.caption(
                "Complements the Sentinel Optimization Workbook / Azure Advisor. "
                "Live Advisor rows appear when SP sync succeeds; demo advisories always included."
            )
            native_df = get_native_recommendations_frame()
            st.dataframe(native_df, use_container_width=True, hide_index=True)
        tab_idx += 1

    if flags["audit"]:
        with tabs[tab_idx]:
            st.markdown("#### Audit results · remediation advisory")
            st.caption(
                f"{metrics['table_count']} table(s) · "
                f"{metrics['ghost_count']} ghost/waste · "
                f"Source: {source_label}"
            )
            display_cols = [
                "Table Name",
                "Category",
                "Size GB/Day",
                "Monthly Cost (USD)",
                "Active Analytics Rules",
                "Status",
                "Ingestion Anomaly Tag",
                "Spike vs MA %",
                "Window Growth %",
                "Projected Monthly Savings (USD)",
                "Tier Recommendation",
                "Detection Risk Note",
                "AI Recommendation",
                "Suggested KQL / DCR Filter",
            ]
            display_cols = [c for c in display_cols if c in filtered_df.columns]
            st.dataframe(
                filtered_df[display_cols],
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Monthly Cost (USD)": st.column_config.NumberColumn(format="$%.2f"),
                    "Projected Monthly Savings (USD)": st.column_config.NumberColumn(
                        format="$%.2f"
                    ),
                    "Size GB/Day": st.column_config.NumberColumn(format="%.2f"),
                    "Spike vs MA %": st.column_config.NumberColumn(format="%.1f"),
                    "Window Growth %": st.column_config.NumberColumn(format="%.1f"),
                    "Status": st.column_config.TextColumn(width="medium"),
                    "Ingestion Anomaly Tag": st.column_config.TextColumn(width="medium"),
                    "Tier Recommendation": st.column_config.TextColumn(width="medium"),
                    "Detection Risk Note": st.column_config.TextColumn(width="large"),
                    "AI Recommendation": st.column_config.TextColumn(width="large"),
                    "Suggested KQL / DCR Filter": st.column_config.TextColumn(width="large"),
                },
            )
            with st.expander("Explain a Ghost / Waste finding", expanded=False):
                waste_only = filtered_df[filtered_df["Status"] == STATUS_WASTE]
                if waste_only.empty:
                    st.write("No Ghost/Waste tables in the current filter set.")
                else:
                    pick = st.selectbox(
                        "Select a waste table",
                        options=waste_only["Table Name"].tolist(),
                        key="waste_explain_pick",
                    )
                    row = waste_only[waste_only["Table Name"] == pick].iloc[0]
                    st.markdown(
                        f"**Status:** `{row['Status']}` · "
                        f"**Cost:** ${float(row['Monthly Cost (USD)']):,.2f}/mo · "
                        f"**Rules:** {int(row['Active Analytics Rules'])}"
                    )
                    st.markdown(f"**Risk note:** {row['Detection Risk Note']}")
                    st.markdown(f"**Recommendation:** {row['AI Recommendation']}")
                    st.code(str(row["Suggested KQL / DCR Filter"]), language="sql")
            st.warning(
                "Detection risk notes are mandatory reading before ingest reduction — "
                "cost governance must not silently weaken detections."
            )
        tab_idx += 1

    if flags["export"]:
        with tabs[tab_idx]:
            st.markdown(
                """
                <div class="panel-card">
                  <div class="panel-title">Export pack</div>
                  <div class="panel-sub">
                    Download board-ready HTML plus FinOps CSV/Excel evidence packs.
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            st.caption(
                f"Exports include anomaly tags for the applied **{anomaly_lookback}d** window · "
                f"{int(metrics.get('anomaly_count', 0))} spike(s) · "
                f"{int(metrics.get('creep_count', 0))} cost-creep table(s)."
            )
            report_html = generate_html_report(
                filtered_df,
                metrics,
                source_label,
                cost_per_gb=cost_per_gb,
            )
            csv_bytes = dataframe_to_csv_bytes(filtered_df)
            c_html, c_csv, c_xlsx = st.columns(3)
            with c_html:
                st.download_button(
                    label="📥 HTML report",
                    data=report_html.encode("utf-8"),
                    file_name=f"sentinel_waste_audit_{stamp}.html",
                    mime="text/html",
                    type="primary",
                    use_container_width=True,
                )
            with c_csv:
                st.download_button(
                    label="📥 CSV (FinOps)",
                    data=csv_bytes,
                    file_name=f"sentinel_waste_audit_{stamp}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            with c_xlsx:
                try:
                    xlsx_bytes = dataframe_to_excel_bytes(
                        filtered_df,
                        sheet_name="Audit",
                        extra_sheets={
                            "Anomalies": anomaly_summary,
                            "IngestTimeSeries": timeseries_df,
                        },
                    )
                    st.download_button(
                        label="📥 Excel workbook",
                        data=xlsx_bytes,
                        file_name=f"sentinel_waste_audit_{stamp}.xlsx",
                        mime=(
                            "application/vnd.openxmlformats-officedocument."
                            "spreadsheetml.sheet"
                        ),
                        use_container_width=True,
                    )
                except Exception as exc:  # noqa: BLE001
                    st.caption(f"Excel export unavailable: {exc}")


def render_empty_state() -> None:
    st.markdown(
        """
        <div class="panel-card">
          <div class="panel-title">Start your interactive cost-governance assessment</div>
          <div class="panel-sub">
            Choose an Assessment Mode, set Cost per GB, optionally enable Service Principal
            live sync, then click <b>Sync Sentinel Metadata</b>.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**1 · Price**\n\nEnter your real Microsoft `$/GB` offer or discount.")
    with c2:
        st.markdown("**2 · Sync**\n\nDemo catalogue or live Usage + rules via SP.")
    with c3:
        st.markdown("**3 · Explore**\n\nTreemap, gauges, what-if simulator, exports.")
    st.info(
        "Recommendations use deterministic expert templates (no LLM). "
        "Internet is required only for live Azure sync / Advisor enrichment."
    )


def main() -> None:
    st.set_page_config(
        page_title="Sentinel Log Waste · DCR Engine",
        page_icon="📉",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_custom_css()
    init_session_state()

    if not is_authenticated():
        render_login_page()
        return

    # Sidebar first so hero can show live mode + $/GB chips.
    categories, min_cost, statuses, cost_per_gb, assessment_mode = render_sidebar(
        st.session_state.get("audit_df")
    )
    render_hero(assessment_mode=assessment_mode, cost_per_gb=cost_per_gb)

    # Admin-configured schedule (checked on each authenticated page load).
    if is_admin():
        maybe_auto_sync(float(cost_per_gb))

    audit_df: pd.DataFrame | None = st.session_state.get("audit_df")

    if st.session_state.get("sync_error"):
        st.error(st.session_state["sync_error"])
    if st.session_state.get("rules_sync_warning") and audit_df is not None:
        st.warning(st.session_state["rules_sync_warning"])
    if st.session_state.get("timeseries_sync_warning") and audit_df is not None:
        st.warning(st.session_state["timeseries_sync_warning"])

    if audit_df is None:
        if is_admin():
            render_empty_state()
        else:
            st.info(
                "No audit data is loaded yet. Ask an **admin** to run "
                "**Sync Sentinel Metadata**, then refresh this page."
            )
        return

    try:
        filtered = apply_sidebar_filters(audit_df, categories, min_cost, statuses)
        if filtered.empty:
            st.warning("No tables match the current sidebar filters. Relax filters to continue.")
            render_metrics(compute_summary_metrics(filtered))
            return
        render_results(
            filtered,
            st.session_state.get("source_label", "Unknown"),
            cost_per_gb=cost_per_gb,
            assessment_mode=assessment_mode,
        )
    except Exception as exc:  # noqa: BLE001
        st.error(f"Unable to render audit results: {exc}")
        st.exception(exc)


if __name__ == "__main__":
    main()
