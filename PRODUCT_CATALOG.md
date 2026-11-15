# Product Catalog  
## AI-Driven Security Log Waste Reduction & DCR Transformation Engine

**Document purpose:** Master product brief for **client demos**, **website copy**, and **presentation decks**.  
**Product type:** Microsoft Sentinel cost-governance, waste audit & remediation advisory platform  
**Operating model:** Read-only metadata / Usage ingestion (no Azure write, update, or delete)  
**Delivery:** Streamlit web application · role-based sign-in · Docker · HTML / CSV / Excel export packs  

> **Tagline:** Know your true Sentinel $/GB waste. Govern access. Catch spikes. Advise the fix — safely.

**Credentials for demos:** listed only in `BUILD_GUIDE.md` (not on the login screen).

---

## 1. Executive summary (website hero / PPT slide 1)

Organizations running **Microsoft Sentinel** often overpay for log ingestion because high-volume tables are collected without enough **analytics-rule coverage**, without **contract-accurate $/GB** math, and without a portable **FinOps + SOC** remediation story.

This product is a **read-only cost-governance engine** that:

1. Prices ingest at the customer’s real **cost_per_gb** (offer / EA / discount)  
2. Correlates table volume against **active analytics rules** (Ghost / Waste detection)  
3. Advises **KQL / DCR transformations** and log **tiering** with detection-risk notes  
4. Detects **ingestion spikes & cost creep** (live Usage daily KQL, with simulation fallback)  
5. Packages results for leadership as **interactive dashboards + HTML/CSV/Excel**  

It **complements** the Microsoft Sentinel Optimization Workbook — it does not replace the Azure portal. It adds **customer pricing**, **rule-gap correlation**, **role separation**, **what-if savings**, **spike trends**, and **shareable audit packs** outside the portal.

---

## 2. Problem statement (for Sentinel customers)

| Pain | Business impact |
| --- | --- |
| Pay-per-GB Analytics ingestion grows silently | Unplanned cloud spend |
| Tables ingested with **0 active analytics rules** (“Ghost tables”) | Cost without detection value |
| Portal cost views use list / estimated rates | Finance cannot match EA/discount reality |
| Optimization Workbook is portal-bound | Hard to share with FinOps / auditors / board |
| Cutting logs without SOC review | Risk of breaking detections |
| Spikes from misconfigured connectors | Sudden bill shocks |
| Shared admin access to cost tools | Weak separation of duties |

---

## 3. Solution overview

```text
Sign in (Admin / Viewer)
        │
        ▼
Sync (Demo catalogue  OR  Live Service Principal)
        │
        ├─ Usage totals (GB by table)
        ├─ Analytics rule dependency counts
        ├─ Daily Usage series (live) / simulation (demo)
        └─ Customer cost_per_gb pricing
        │
        ▼
Correlation + Anomaly + Remediation engines
        │
        ▼
Interactive dashboards · What-if · Exports
```

**Value equation**

```text
Monthly Cost (USD) = Size_GB_Day × 30 × cost_per_gb
Waste = high cost + weak/zero analytics-rule dependency
Savings = advisory DCR / filter / tiering opportunity (what-if adjustable)
```

---

## 4. Who it is for

| Audience | How the product helps |
| --- | --- |
| **CIO / CISO** | Annual waste exposure, prioritized tables, board-ready summary |
| **FinOps / Cloud Finance** | Contract $/GB, Top waste tables, CSV/Excel, what-if savings |
| **SOC / Detection Engineering** | Rule coverage vs cost, detection risk notes, KQL starting points |
| **Sentinel / Azure Admins** | SP sync, schedule, live Usage, Ghost-table cleanup backlog |
| **Internal Audit / GRC** | Read-only evidence trail, exports, role separation |
| **Partners / MSSPs** | Repeatable customer assessment offering (Dockerized) |

---

## 5. Complete feature catalog

### 5.1 Access control & security UX

| Feature | Description | Org benefit |
| --- | --- | --- |
| Sign-in gate | Login required before dashboard | Controlled access for demos & assessments |
| **Admin** role | Pricing, SP, sync frequency, Sync button | Configuration ownership |
| **Viewer** role | Dashboards + filters + exports only | Safe consumption for FinOps/SOC viewers |
| Sign out | Session end from sidebar | Clean handoff in demos |
| Credentials offline | Documented in BUILD_GUIDE, not on login UI | Cleaner security posture for presentations |

### 5.2 Customer pricing (`cost_per_gb`)

| Feature | Description | Org benefit |
| --- | --- | --- |
| Portal $/GB override | Admin enters real Microsoft offer / EA / discount | Finance-accurate costing |
| Instant reprice | Changing $/GB recalculates costs without re-query | “What if our new EA rate is X?” modeling |
| Viewer rate display | Viewers see applied rate read-only | Transparency without edit rights |

**Formula:** `Monthly Cost = Size_GB_Day × 30 × cost_per_gb`

### 5.3 Data sync (demo + live Sentinel)

| Feature | Description | Org benefit |
| --- | --- | --- |
| Demo catalogue sync | Built-in realistic Sentinel tables | Offline viva / sales demo |
| Live Service Principal sync | Tenant ID, Client ID, Secret, workspace IDs | Real customer tenant assessment |
| Usage totals KQL | Billable GB by DataType | Accurate table cost drivers |
| Analytics rules API | Enabled rule list → table dependency heuristic | Ghost-table detection |
| **Daily Usage KQL** | ~31-day GB/day by table cached at sync | Real spike / creep charts |
| Simulation fallback | If daily Usage fails or demo mode | Demo never breaks |
| Sync frequency | Manual / 1 hour / daily / weekly | Lightweight governance cadence |
| Read-only guarantee | No DCR/rule writes | Safe for production tenants |

**Least-privilege Azure roles (recommended):** Log Analytics Reader · Microsoft Sentinel Reader · (optional) Advisor Reader.

### 5.4 Correlation engine (Ghost / Waste detection)

| Status | Meaning | Org action |
| --- | --- | --- |
| **Waste / Ghost** | Ingest with no (or effectively unused) analytics-rule dependency | Filter via DCR, disable connector noise, or add detections |
| **Underutilized** | High volume with very few rules | Tighten filters; align content pack |
| **Active** | Meaningful rule coverage | Prefer column pruning over broad drops |

Also produces:

- Projected monthly / annual savings heuristics  
- **Tier recommendation** (Analytics vs Basic/Auxiliary candidates)  
- **Detection risk notes** (SOC change-control awareness)  
- **AI-style KQL / DCR filter suggestions** (deterministic templates, no LLM required)

### 5.5 Assessment modes

| Mode | Focus | Best for |
| --- | --- | --- |
| **Full assessment** | All panels | Deep workshops |
| **Executive view** | Summary, business case, what-if, spikes, trend, export | Leadership demos |
| **FinOps view** | Cost, what-if, charts, spikes, native tips, audit, export | Finance reviews |
| **SOC view** | Charts, coverage bubble, spikes, native tips, audit, export | Detection teams |

### 5.6 Interactive command center (dashboard UX)

| Feature | Description | Org benefit |
| --- | --- | --- |
| KPI cards | Monthly spend, waste, monthly/annual savings, savings % | Instant health check |
| Waste-share progress | Visual % of spend that is Ghost/Waste | Executive clarity |
| Cost treemap | Click-to-zoom cost by status → table | Find offenders fast |
| Savings gauge | Opportunity % indicator | Board-friendly visual |
| Top-N cost bars | Highest monthly cost tables | Cleanup prioritization |
| What-if simulator | Slider for DCR effectiveness + before/after chart | Pre-change savings rehearsal |
| Themed UI | Brand colors, cards, chips | Product-quality demo experience |

### 5.7 Dashboard tabs (full function map)

| Tab | Functions | Helps organization by… |
| --- | --- | --- |
| **Executive** | Board bullets, ROI blurb, anomaly counts, status legend | Leadership storytelling |
| **Business case** | Top waste tables, annual savings metrics, ROI narrative | Funding cleanup projects |
| **Ingestion Spikes & Trends** | Apply 1 Day / 1 Week / 1 Month / Custom; spike tags; today-vs-MA chart; cost-creep lines; live/sim source label | Catch bill shocks & silent growth |
| **Visual analytics** | Volume vs cost bars, status pie, coverage-vs-cost bubbles | Multi-angle analysis |
| **Governance trend** | Spend/waste/savings history across syncs | Continuous control evidence |
| **Native recommendations** | Demo Microsoft-style tips + optional live Azure Advisor Cost | Align with Microsoft guidance |
| **Audit & remediation** | Full table with status, anomaly tags, tiering, risk notes, KQL; explain-a-Ghost expander | Actionable cleanup backlog |
| **Export pack** | HTML + CSV + Excel (Audit / Anomalies / IngestTimeSeries sheets) | Share outside Azure portal |

### 5.8 Spikes & Trends (anomaly engine) — detail

**Purpose:** Detect sudden volume spikes and longer cost creep without storing raw security logs.

| Control / output | Detail |
| --- | --- |
| Apply range | **1 Day · 1 Week · 1 Month · Custom (1–90)** + **Apply range** button |
| Baseline | Adaptive moving average (e.g. 7-day MA on month view) |
| 🚨 Spike | Today &gt; **50%** above baseline MA |
| 🟡 Elevated | Today &gt; **25%** above baseline MA |
| 🟢 Normal | Within baseline variance |
| Cost creep | Window ≥ 7 days and growth ≥ **20%** |
| Live source | Daily `Usage` KQL cached at SP sync |
| Fallback | Deterministic simulation from current Size GB/Day |

**Org benefit:** FinOps sees *when* cost changed; SOC/admins see *which connector/table* spiked — before the invoice arrives.

### 5.9 Filters & cleanup focus

| Filter | Description | Org benefit |
| --- | --- | --- |
| Log category | Multiselect | Scope by domain (Identity, Network, etc.) |
| Minimum monthly cost | Free number box (not capped by dataset max) | Budget-driven cleanup (“show only &gt; $X”) |
| Status | Waste / Underutilized / Active | Focus Ghost tables first |

### 5.10 Export & evidence pack

| Format | Contents | Typical consumer |
| --- | --- | --- |
| **HTML** | Styled audit report, KPIs, anomaly counts, recommendations | Steering committee email |
| **CSV** | Flat audit + anomaly columns | FinOps models / Excel pivot |
| **Excel** | Sheets: Audit, Anomalies, IngestTimeSeries | Formal assessment deliverable |

All exports respect current sidebar filters and the applied anomaly window.

### 5.11 Delivery & operations

| Feature | Description |
| --- | --- |
| Local run | `streamlit run app.py` |
| Docker | `Dockerfile` + `docker-compose.yml` on port **8501** |
| Theme | `.streamlit/config.toml` |
| History file | `data/audit_history.json` (governance KPI snapshots) |
| Docs | `BUILD_GUIDE.md` (build/run/accounts) · this catalog (product story) |

---

## 6. How it helps Sentinel organizations (outcome map)

### 6.1 Cost governance
- Replace guesswork with **contract $/GB** math  
- Quantify **Ghost-table waste** in monthly and annual USD  
- Run **what-if** DCR effectiveness before change tickets  
- Spot **spikes and creep** early with Usage trends  

### 6.2 Security operations
- See which expensive tables lack detections  
- Get **KQL / DCR** starting points without auto-deploy risk  
- Read **detection risk notes** before cutting ingest  
- Keep Optimization Workbook / Advisor as complementary native insight  

### 6.3 Audit & compliance
- Read-only assessment model suitable for controlled tenants  
- Role separation (configure vs view)  
- Exportable evidence for reviews and MSSP deliverables  
- Transparent thresholds (documented heuristics, no black-box LLM)  

### 6.4 Operating model advantage vs portal-only

| Need | Portal Optimization Workbook | This product |
| --- | --- | --- |
| Customer $/GB | Limited / estimated | First-class admin input |
| Ghost-table vs rules | Partial / manual | Automated correlation |
| Share with FinOps offline | Difficult | HTML/CSV/Excel |
| Role-separated assessment UX | IAM/portal complexity | Admin / Viewer app roles |
| What-if savings rehearsal | Limited | Interactive simulator |
| Spike window 1d/7d/30d Apply | Manual KQL | Built-in UX + live/sim |
| Safe for production | Observational | Read-only by design |

---

## 7. Typical client engagement / demo storyboard (PPT flow)

| Slide / step | Action | Message |
| --- | --- | --- |
| 1 | Problem | Sentinel ingest waste is invisible until the bill |
| 2 | Sign in Admin | Controlled access |
| 3 | Set cost_per_gb | “Your EA rate, not list price” |
| 4 | Sync demo or live | Metadata + rules + daily Usage |
| 5 | Command center | Treemap / gauge / Top waste |
| 6 | What-if | “If we filter 70% of Ghost volume…” |
| 7 | Spikes tab | Apply 1 Week / 1 Month — show 🚨 tags |
| 8 | Audit tab | Risk notes + KQL advice |
| 9 | Export | Board pack in one click |
| 10 | Sign in Viewer | SoD: consume without changing SP |
| 11 | Close | Complements Microsoft workbook; advises, never writes |

---

## 8. Website content blocks (ready to reuse)

### Hero
**AI-Driven Security Log Waste Reduction & DCR Transformation Engine**  
Price Sentinel ingest at your real $/GB. Find Ghost tables. Catch spikes. Export the business case — read-only.

### Primary CTA
**Run assessment** · **Book a demo** · **Download sample HTML report**

### Three pillars
1. **Cost truth** — customer `cost_per_gb` + annual savings  
2. **Detection alignment** — volume × analytics-rule dependency  
3. **Safe remediation** — advisory KQL/DCR + risk notes + exports  

### Trust line
Read-only Azure access · No raw log warehouse · Complements Sentinel Optimization Workbook  

---

## 9. Security & compliance posture

- No Azure resource mutation (no DCR deploy, no rule create/update)  
- Live mode uses OAuth2 client credentials (Service Principal) with least privilege  
- SP secrets stay in session inputs (not baked into Docker images)  
- Spike analysis uses **Usage aggregates**, not raw security event payloads  
- Demo passwords are academic/demo-only (see BUILD_GUIDE); production should use Entra ID / hashed store  
- Recommendations require human change control before Azure implementation  

---

## 10. Technical snapshot (for website “Platform” page)

| Layer | Technology |
| --- | --- |
| UI | Streamlit + custom CSS theme |
| Charts | Plotly (treemap, gauge, bars, lines, bubbles) |
| Data | pandas |
| Live Azure | requests · Log Analytics Query API · Sentinel alertRules · Advisor (optional) |
| Auth (demo) | Hardcoded Admin/Viewer users |
| Packaging | Docker / Compose · Python 3.12 |

**Core engines inside `app.py`:** sync · correlation · anomaly/trend · what-if · native tips · HTML/CSV/Excel exporters · role-aware UI.

---

## 11. Roadmap ideas (future website “Coming soon”)

- Entra ID / SSO login  
- SQLite encrypted SP + schedule store  
- Background worker for exact hourly sync  
- Auto-map live Usage daily series without simulation fallback  
- Multi-workspace compare  
- PDF board pack  

---

## 12. Repository map

| Artifact | Use |
| --- | --- |
| `app.py` | Full product application |
| `BUILD_GUIDE.md` | Install, Docker, architecture, **demo accounts** |
| `PRODUCT_CATALOG.md` | This document — website & PPT master |
| `.streamlit/config.toml` | Visual theme |
| `Dockerfile` / `docker-compose.yml` | Container delivery |
| `data/` | Governance trend history |
| `requirements.txt` | Dependencies |

---

## 13. One-paragraph synopsis (abstract / LinkedIn / RFP)

> The AI-Driven Security Log Waste Reduction & DCR Transformation Engine is a read-only Microsoft Sentinel cost-governance platform that prices log ingestion at the customer’s real cost-per-GB, correlates table volume with active analytics-rule dependency to expose Ghost/Waste spend, detects ingestion spikes and cost creep from Usage daily aggregates (with demo simulation fallback), and produces interactive FinOps/SOC dashboards plus HTML/CSV/Excel remediation packs—complementing the Sentinel Optimization Workbook without writing changes back to Azure.

---

**Catalog tagline:**  
**Know your true Sentinel $/GB waste. Govern access. Catch spikes. Advise the fix — safely.**
