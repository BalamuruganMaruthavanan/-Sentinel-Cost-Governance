# AI-Driven Security Log Waste Reduction & DCR Transformation Engine

**MCA Final-Year Project — Complete Build & Architecture Guide**

This guide explains the architecture, build steps, read-only API integration flow, and local execution instructions for the Streamlit application in this repository.

---

## 1. Project overview

### Problem statement

Microsoft Sentinel / Log Analytics workspaces often ingest high volumes of security and operational telemetry. A significant share of that volume may never be referenced by **active analytics rules**, creating **financial waste** (pay-per-GB ingestion) without improving detection coverage.

### Solution

This application is a **read-only metadata audit and recommendation engine** that:

1. Accepts the customer’s real **$/GB** Microsoft offer or discounted Analytics rate in the portal.
2. Ingests workspace table usage metadata from a **demo catalogue** or **live customer tenant** (Service Principal).
3. Correlates ingest volume against analytics-rule dependency.
4. Flags **Ghost Tables** / **Waste Data** (high volume, zero active rules).
5. Generates **AI-driven KQL / Data Collection Rule (DCR) transformation** recommendations.
6. Exports a professionally styled **HTML audit report** for academic review and stakeholder presentation.

### Non-negotiable operating model

| Allowed | Not allowed |
| --- | --- |
| Read-only metadata sync (demo catalogue or live SP Usage + rules APIs) | Creating / updating / deleting Sentinel resources |
| Customer-entered $/GB cost overrides | Writing DCRs back to Azure |
| In-memory correlation & recommendations | Bulk raw log export dumps into the app |
| HTML export of advisory findings | Mutating analytics rules or workspace tables |

All recommendations are **advisory**. Any real DCR change must go through human change control outside this tool.

---

## 2. Repository structure

```text
MCA project/
├── app.py              # Main Streamlit application (modular, single-file for easy demo)
├── requirements.txt    # Python dependencies (includes openpyxl for Excel export)
├── Dockerfile          # Container image for Streamlit on port 8501
├── docker-compose.yml  # One-command local/container run
├── .dockerignore       # Keep build context lean/safe
├── data/               # Governance trend history (audit_history.json)
├── .streamlit/
│   └── config.toml     # Theme + browser/server UI settings
├── PRODUCT_CATALOG.md  # Product value catalog (cost_per_gb, audit, governance)
└── BUILD_GUIDE.md      # This document
```

`app.py` is intentionally self-contained for viva / presentation reliability, but is **internally modular** with clearly separated sections:

| Section | Responsibility |
| --- | --- |
| Configuration & constants | Default pricing, demo catalogue, KQL templates, API URLs |
| Read-only metadata ingestion | Demo builder + Service Principal live Usage/rules sync |
| Correlation engine | Ghost / Waste / Underutilized / Active classification |
| Metrics & filters | KPI math and sidebar filter logic |
| Plotly builders | Cost/volume bar chart and status pie chart |
| HTML exporter | Self-contained styled audit report |
| Streamlit UI | Pricing, SP credentials, sync, filters, table, download |

---

## 3. Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│                     Streamlit UI (app.py)                         │
│  $/GB pricing · SP credentials · Filters · KPIs · Charts · Export │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                ┌───────────────▼───────────────┐
                │  Sync Sentinel Metadata       │
                └───────────────┬───────────────┘
                                │
         ┌──────────────────────┼──────────────────────────┐
         ▼                                                 ▼
┌─────────────────────┐                     ┌─────────────────────────────────┐
│ Demo catalogue      │                     │ Live Service Principal sync     │
│ (built-in tables)   │                     │ 1) OAuth client credentials     │
│ Always available    │                     │ 2) Usage KQL (billable GB)      │
└─────────┬───────────┘                     │ 3) Sentinel alertRules (GET)    │
          │                                 └─────────────────┬───────────────┘
          └──────────────────┬────────────────────────────────┘
                             ▼
               ┌─────────────────────────────┐
               │ Apply customer $/GB pricing │
               │ Monthly = GB/Day × 30 × $   │
               └──────────────┬──────────────┘
                              ▼
               ┌─────────────────────────────┐
               │ Correlation Engine          │
               │ Size × Active Rules → Status│
               │ + savings + AI KQL / DCR    │
               └──────────────┬──────────────┘
                              ▼
               ┌─────────────────────────────┐
               │ Charts · Table · HTML export│
               └─────────────────────────────┘
```

### Correlation rules (transparent academic thresholds)

| Status | Condition | Savings heuristic |
| --- | --- | --- |
| **Waste / Ghost** | `Active Analytics Rules == 0` (high-volume tables emphasized at ≥ 5 GB/day) | ~70% of monthly cost |
| **Underutilized** | `1–2` rules **and** size ≥ 15 GB/day | ~35% of monthly cost |
| **Active** | Remaining tables with meaningful rule coverage | ~10% optimization via column pruning |

### Customer pricing formula

```text
Monthly Cost (USD) = Size_GB_Day × 30 × Customer_Cost_Per_GB
```

- Default portal rate: **$2.76 / GB** (demo only).
- Customers override this in **Customer Pricing → Cost per GB (USD)** with their Microsoft offer / EA / discounted rate.
- Changing $/GB after sync **reprices cached volumes in memory** (no Azure re-query required).

---

## 4. Technology stack

| Package | Role |
| --- | --- |
| **streamlit** | Interactive web UI and session state |
| **pandas** | Metadata tabular processing |
| **requests** | OAuth token + Log Analytics Query API + Sentinel alertRules GET |
| **plotly** | Enterprise charts (volume/cost bars, pie, coverage scatter, trends) |
| **openpyxl** | Excel (.xlsx) export for FinOps / audit packs |

Declared in `requirements.txt`.

Product positioning and organizational value (cost_per_gb, audit, governance) are documented in **`PRODUCT_CATALOG.md`**.

---

## 5. API integration flow (read-only)

### 5.1 Customer pricing (always on)

1. Enter **Cost per GB (USD)** in the sidebar (default `2.76`).
2. On sync, every table’s monthly cost uses that rate.
3. After sync, changing the rate **reprices** cached `Size GB/Day` values without calling Azure again.

### 5.2 Demo path (default — recommended for viva without Azure)

1. Leave **Live sync with Service Principal** unchecked.
2. Click **🔄 Sync Sentinel Metadata**.
3. `build_demo_metadata(cost_per_gb)` loads `DEMO_TABLE_CATALOGUE`.
4. Correlation + recommendations run in memory.

### 5.3 Live Service Principal path (customer tenant)

1. Enable **Live sync with Service Principal**.
2. Enter:
   - Tenant ID  
   - Client ID (App registration)  
   - Client Secret  
   - Subscription ID  
   - Resource Group  
   - Workspace Name  
   - Workspace ID (Log Analytics GUID / customer ID)  
3. Click **🔄 Sync Sentinel Metadata**.
4. The app:
   1. Requests an OAuth2 **client-credentials** token for `https://api.loganalytics.azure.com/.default`
   2. Runs a read-only **Usage** KQL query (Microsoft Learn billable-volume pattern: `sum(Quantity)/1000` by `DataType`)
   3. Requests a second token for `https://management.azure.com/.default`
   4. **GET**s Sentinel `alertRules` and counts enabled rules whose KQL references each table
   5. Applies portal `$/GB` → monthly cost → correlation engine

**Official documentation categories**

- Microsoft identity platform — OAuth2 client credentials flow  
- Microsoft Learn — Azure Monitor Log Analytics Query API  
- Microsoft Learn — Analyze usage (`Usage` table)  
- Microsoft Learn — Microsoft Sentinel alert rules REST API  

**Required Azure RBAC (least privilege)**

| Role | Why |
| --- | --- |
| Log Analytics Reader | Query `Usage` (and related read queries) |
| Microsoft Sentinel Reader | List analytics / alert rules |

**Security notes**

- Client secrets stay in Streamlit session inputs only — never commit them.
- Prefer a dedicated App Registration with Reader roles only.
- Live mode errors are shown in the UI; previous results are retained when possible.
- If rules API fails but Usage succeeds, volumes still load and rule counts default to `0` with a warning.

### 5.4 What is intentionally *not* integrated

- Data Collection Rule create/update APIs  
- Analytics rule create/update APIs  
- Workspace purge / table retention mutations  
- Bulk export of raw security event payloads into the Streamlit process  
- Any `PUT` / `PATCH` / `DELETE` against Sentinel resources  

---

## 6. Feature map (UI)

| Feature | Where | Behaviour |
| --- | --- | --- |
| Assessment mode | Sidebar | Executive / FinOps / SOC / Full presets |
| Cost per GB | Sidebar | Customer offer / discounted $/GB override |
| Live SP toggle | Sidebar | Demo vs live tenant sync |
| SP + workspace fields | Sidebar expander | Tenant, Client ID/Secret, sub, RG, workspace |
| Sync button | Sidebar | Loads metadata + runs correlation + history snapshot |
| Category / cost / status filters | Sidebar | Audit scope controls |
| KPI cards | Main pane | Styled metric cards + waste-share progress bar |
| Interactive command center | Main pane | Cost treemap, savings gauge, Top-N bars, live what-if chart |
| Executive summary | Tab | Deterministic board bullets + ROI blurb |
| Business case | Tab | Top waste tables + ROI narrative |
| Visual analytics | Tab | Grouped bars, pie, coverage-vs-cost bubble chart |
| Governance trend | Tab | Spend/waste/savings history across syncs |
| Native recommendations | Tab | Demo + optional live Azure Advisor Cost rows |
| Audit & remediation | Tab | Tiering, detection risk notes, KQL/DCR advice |
| Export pack | Tab | HTML + CSV + Excel downloads |

---

## 7. Local build & execution

### Prerequisites

- Python **3.10+** (3.11/3.12 recommended)
- `pip` available on `PATH`
- Outbound internet only required if you install packages from PyPI or attempt the optional live API path

### Step 1 — Open a terminal in the project folder

**Windows (PowerShell):**

```powershell
cd "C:\Transcripts\MCA project"
```

**macOS / Linux:**

```bash
cd "/path/to/MCA project"
```

### Step 2 — Create and activate a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If execution policy blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Run the Streamlit application

```bash
streamlit run app.py
```

Expected console output includes a local URL such as:

```text
Local URL: http://localhost:8501
```

Open that URL in a browser.

### Step 4b — Sign in (hardcoded demo users)

The app requires sign-in before the dashboard loads. Users are **hardcoded in `app.py`** for the MCA demo (no database yet).

| Username | Password | Role | Permissions |
| --- | --- | --- | --- |
| `admin` | `Admin@123` | **Admin** | Update **Cost per GB**, configure **Service Principal**, set **sync frequency** (Manual / 1 hour / Daily / Weekly), run **Sync**, full dashboards + exports |
| `viewer` | `Viewer@123` | **Viewer** | View dashboards, filters, charts, exports only — cannot change SP, pricing, or sync |
| `finops` | `FinOps@123` | **Viewer** | Same as viewer (FinOps-oriented demo account) |

**Role behaviour**

- **Admin:** Workspace Controls (SP expander, live sync toggle, sync frequency, Sync button) + pricing override.  
- **Viewer:** Sees applied `$/GB` and last sync info as read-only; uses Assessment Mode + Audit Filters + interactive dashboards/exports.  
- **Sign out** is available at the top of the sidebar.

**Sync frequency (admin)**

| Option | Behaviour |
| --- | --- |
| Manual only | Sync only when Admin clicks **Sync Sentinel Metadata** |
| Every 1 hour | On page load, auto-sync if last sync older than 1 hour |
| Once a day | Auto-sync if last sync older than 24 hours |
| Once a week | Auto-sync if last sync older than 7 days |

Scheduled sync uses the admin’s saved SP settings when “Live sync” is enabled; otherwise it refreshes the demo catalogue. This is a lightweight page-load check (no separate worker process).

**Live daily Usage for Spikes & Trends**

During **Live sync with Service Principal**, the app also runs a read-only daily `Usage` KQL query (billable GB by table by day, ~31 days) and caches it in session for the **📈 Ingestion Spikes & Trends** tab.

| Mode | Spikes & Trends history source |
| --- | --- |
| Live sync + daily Usage OK | Real Sentinel `Usage` daily aggregates |
| Live sync but daily Usage fails | **Simulation fallback** (warning shown; table totals still load) |
| Demo sync | Simulation from current `Size GB/Day` snapshot |

Apply range (**1 Day / 1 Week / 1 Month**) filters the cached live series locally (or resimulates in demo mode). Raw security logs are never stored — only Usage volume aggregates.

**Security note for evaluators:** these passwords are intentional demo credentials for academic presentation only. Do not reuse in production; replace with Entra ID / SQLite hashed users later.

### Step 4c — Sidebar collapse / expand (bug fix)

Earlier UI polish hid the Streamlit `header`, which also hid the control to reopen the sidebar after clicking **≪**.

- The app **no longer hides `header`**, so **≫** remains available to expand the sidebar again.  
- Tip is also shown in the sidebar after login.  
- If the sidebar is still missing, refresh the browser (`F5`).

### Step 5 — Run with Docker

Use Docker when you want a consistent demo environment without installing Python packages on the host. The project ships with:

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds the Streamlit app image (`python:3.12-slim`, port **8501**) |
| `docker-compose.yml` | One-command build + run |
| `.dockerignore` | Excludes `.venv`, secrets, and cache from the build context |

#### Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine (Linux)
- Docker Compose v2 (`docker compose` plugin)
- Confirm Docker is running:

```powershell
docker version
docker compose version
```

#### What the Dockerfile does

1. Uses official `python:3.12-slim` base image  
2. Installs `curl` + CA certificates (health check + HTTPS for live Azure sync)  
3. Installs Python packages from `requirements.txt`  
4. Copies `app.py` (and `BUILD_GUIDE.md`) into `/app`  
5. Runs as non-root user `appuser`  
6. Exposes port **8501**  
7. Health-checks `http://localhost:8501/_stcore/health`  
8. Starts Streamlit with `--server.address=0.0.0.0` (required inside containers)

Official source category: **Streamlit Docs — Deploy Streamlit using Docker**.

---

#### Option A — Build and run with Docker CLI

**1. Go to the project folder**

```powershell
cd "C:\Transcripts\MCA project"
```

```bash
cd "/path/to/MCA project"
```

**2. Build the image**

```powershell
docker build -t mca-sentinel-waste-engine:latest .
```

Expected result: image tagged `mca-sentinel-waste-engine:latest`.

Verify:

```powershell
docker images mca-sentinel-waste-engine
```

**3. Run the container (foreground)**

```powershell
docker run --rm -p 8501:8501 --name mca-sentinel-waste-engine mca-sentinel-waste-engine:latest
```

| Flag | Meaning |
| --- | --- |
| `--rm` | Remove container when it stops |
| `-p 8501:8501` | Map host port 8501 → container port 8501 |
| `--name ...` | Friendly container name |

**4. Open the app**

Browser: **http://localhost:8501**

**5. Stop the container**

- Foreground: `Ctrl+C`  
- Or from another terminal:

```powershell
docker stop mca-sentinel-waste-engine
```

**Useful run variants**

Detached (background):

```powershell
docker run -d --rm -p 8501:8501 --name mca-sentinel-waste-engine mca-sentinel-waste-engine:latest
docker logs -f mca-sentinel-waste-engine
docker stop mca-sentinel-waste-engine
```

Different host port (if 8501 is busy), e.g. host `8502`:

```powershell
docker run --rm -p 8502:8501 --name mca-sentinel-waste-engine mca-sentinel-waste-engine:latest
```

Then open **http://localhost:8502**.

Rebuild after code changes:

```powershell
docker build -t mca-sentinel-waste-engine:latest .
docker stop mca-sentinel-waste-engine
docker run --rm -p 8501:8501 --name mca-sentinel-waste-engine mca-sentinel-waste-engine:latest
```

---

#### Option B — Build and run with Docker Compose (recommended)

**1. Go to the project folder**

```powershell
cd "C:\Transcripts\MCA project"
```

**2. Build and start**

Foreground:

```powershell
docker compose up --build
```

Detached:

```powershell
docker compose up --build -d
```

**3. Open the app**

Browser: **http://localhost:8501**

**4. View logs / status**

```powershell
docker compose ps
docker compose logs -f
```

**5. Stop and remove**

```powershell
docker compose down
```

Rebuild cleanly after dependency changes:

```powershell
docker compose build --no-cache
docker compose up -d
```

---

#### Docker verification checklist

- [ ] `docker build` / `docker compose up --build` completes without errors  
- [ ] Health status becomes healthy (`docker ps` shows healthy, or Compose service is up)  
- [ ] http://localhost:8501 loads the dashboard  
- [ ] Demo sync works inside the container  
- [ ] Live SP sync works only if the container has outbound HTTPS to Azure  

#### Docker security notes

- Do **not** bake Tenant ID / Client Secret into the image or `docker-compose.yml`.  
- Enter Service Principal details in the Streamlit sidebar at runtime (session-only).  
- `.dockerignore` keeps `.env` and local venv out of the build context.

#### Docker troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Port already allocated | Host 8501 in use | Use `-p 8502:8501` or stop the other process |
| `docker` not recognized | Docker Desktop not installed/running | Start Docker Desktop and retry |
| Build fails on pip | Network / PyPI blocked | Check proxy/DNS; retry build |
| App not reachable | Forgot `-p` publish | Always map `-p 8501:8501` |
| Live Azure sync fails in container | No outbound HTTPS / wrong SP roles | Allow internet egress; verify Reader roles |
| Old code still running | Stale image layer | `docker compose build --no-cache` then `up -d` |

### Step 6 — Demo script (viva / presentation)

1. Sign in as `admin` / `Admin@123`.
2. Confirm the hero banner shows **READ-ONLY METADATA MODE** and role chip `admin`.
3. Set **Cost per GB** (e.g. `2.76`, then change to a discounted rate like `2.30` after sync to show repricing).
4. Click **🔄 Sync Sentinel Metadata** (demo mode).
5. Point to KPI cards, treemap, gauge, and what-if simulator.
6. Filter sidebar to **Waste / Ghost** only — show Ghost Tables.
7. Sign out, then sign in as `viewer` / `Viewer@123` to show view-only controls.
8. (Optional live, admin) Enable SP sync, enter tenant credentials, set sync frequency, sync again.
9. Click **📥 Export** (HTML/CSV/Excel) and open the downloaded file.

---

## 8. Presentation talking points

1. **Cost visibility:** Ingestion is priced by volume; unused tables are silent budget burn.
2. **Correlation insight:** Waste is not “large tables” alone — it is **volume without detection dependency**.
3. **Remediation path:** DCR transformations / KQL ingestion filters reduce volume **before** paid analytics retention.
4. **Safety:** The engine recommends; operators approve and deploy via standard Azure change control.
5. **Extensibility:** Demo catalogue today; read-only Management API wiring tomorrow — same correlation and export pipeline.

---

## 9. Error handling & academic resilience

The application is designed not to fail mid-demo:

- Missing / incomplete live credentials → silent fallback to demo data.
- Invalid metadata schema → captured as `sync_error` and shown in the sidebar / main pane.
- Empty filter results → warning + empty metrics, no crash.
- Chart/table/export failures → surfaced with `st.error` while keeping the session usable.

Session state keys:

| Key | Purpose |
| --- | --- |
| `audit_df` | Enriched correlation results |
| `volume_df` | Cached size + rule counts for $/GB refresh |
| `portal_cost_per_gb` | Sidebar customer pricing widget value |
| `applied_cost_per_gb` | Rate last applied to the audit frame |
| `source_label` | Demo vs live source description |
| `last_sync_utc` | Timestamp of last successful sync |
| `sync_error` | Last sync failure message (if any) |
| `rules_sync_warning` | Usage OK but rules API failed |

---

## 10. Customisation guide

| Goal | Where to edit in `app.py` |
| --- | --- |
| Change demo tables / volumes | `DEMO_TABLE_CATALOGUE` |
| Change default $/GB | `DEFAULT_COST_PER_GB_USD` |
| Tune Ghost / Underutilized thresholds | `classify_table()` |
| Add table-specific KQL advice | `KQL_RECOMMENDATIONS` |
| Restyle HTML export | `generate_html_report()` CSS block |
| Change Usage lookback / KQL | `USAGE_LOOKBACK_DAYS`, `USAGE_KQL` |
| Change Sentinel API version | `ARM_ALERT_RULES_URL` |

---

## 11. Verification checklist

- [ ] `pip install -r requirements.txt` completes without errors  
- [ ] `streamlit run app.py` opens the dashboard  
- [ ] `docker compose up --build` serves the app on port 8501  
- [ ] Sync button populates metrics and charts  
- [ ] Filtering to **Waste / Ghost** isolates unused high-volume tables  
- [ ] Interactive table shows AI recommendations and KQL filters  
- [ ] HTML export downloads and opens in a browser with KPIs + table  
- [ ] No Azure write operations are present in code paths used by the demo  

---

## 12. Academic declaration (suggested wording)

> This project analyses Microsoft Sentinel log ingestion economics using a **read-only metadata ingestion model**. It correlates table sizes with active analytics rule dependencies to identify financial waste and produces advisory KQL / DCR transformation recommendations. The system does not modify Azure resources; all remediation actions remain under human operational control.

---

## 13. Official source categories used

When extending beyond the demo catalogue, consult:

- **Microsoft Learn** — Microsoft Sentinel / Azure Monitor Logs pricing & ingestion concepts  
- **Microsoft Learn** — Analyze usage in a Log Analytics workspace (`Usage` table)  
- **Microsoft Learn** — Azure Monitor Query API / Log Analytics query endpoint  
- **Microsoft Learn** — Microsoft Sentinel alert rules REST API  
- **Microsoft identity platform** — OAuth2 client credentials (Service Principal)  
- **Microsoft Learn** — Data Collection Rules (DCR) and transformation KQL  
- **Plotly documentation** — bar / pie chart layouts  
- **Streamlit documentation** — session state, metrics, download button, dataframe column config  

---

## 14. Quick troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `streamlit` not found | venv not activated or deps not installed | Activate `.venv`, re-run `pip install -r requirements.txt` |
| Port already in use | Another Streamlit instance | `streamlit run app.py --server.port 8502` |
| Live sync fails on token | Wrong Tenant/Client/Secret | Verify App Registration secret and tenant ID |
| Live sync fails on query | Missing Workspace ID GUID or LA Reader role | Confirm workspace customer ID and RBAC |
| Rules all show 0 | Sentinel Reader missing / query has no table names | Grant Sentinel Reader; check rule KQL references |
| Costs look wrong after rate change | Forgot that formula is GB/Day × 30 × $/GB | Adjust **Cost per GB**; volumes stay cached |
| Blank charts | Filters excluded all rows | Reset category/status filters and min cost slider |

---

**End of build guide.**  
For questions during evaluation, walk through Section 3 (architecture), Section 5 (read-only API flow), and Section 7 Step 5 (live demo script).
