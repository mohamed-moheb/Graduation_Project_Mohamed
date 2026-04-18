# ATT&CKsmith 🔐

> **AI-Driven System for Mapping Indicators of Compromise to MITRE ATT&CK Techniques and Orchestrating Defensive Rule Generation**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB?logo=react&logoColor=black)](https://reactjs.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-Academic-lightgrey)](LICENSE)

---

## Overview

ATT&CKsmith is an end-to-end threat intelligence pipeline that transforms raw Indicators of Compromise (IOCs) into actionable security intelligence. Submitted IOCs are enriched using five external threat intelligence platforms, mapped to MITRE ATT&CK techniques using the Foundation-Sec-8B-Instruct large language model, validated through a three-rule RAG validation layer, scored for risk, and converted into deployable Wazuh XML detection rules. The system further identifies probable threat actor groups (APTs), predicts the attacker's next likely technique, and generates proactive detection rules in anticipation of that technique.

ATT&CKsmith also supports **multi-IOC campaign analysis**, correlating indicators from the same incident to produce a unified kill chain map, shared technique detection, a consolidated rule set, and stronger APT attribution through technique aggregation.

This project was developed as a graduation dissertation for the BSc Ethical Hacking and Cybersecurity programme at Coventry University – The Knowledge Hub Universities.

---

## Key Features

- **IOC Enrichment** — Queries VirusTotal, AbuseIPDB, Shodan, MalwareBazaar, and URLScan.io in parallel. Falls back to analyst-provided context when no external data exists.
- **LLM-Based ATT&CK Mapping** — Foundation-Sec-8B-Instruct (Cisco, built on Llama 3.1) maps IOCs to MITRE ATT&CK technique IDs with behavioural justifications.
- **RAG Validation** — Three-rule backend validation layer prevents hallucinated or revoked technique IDs from reaching the analyst: ATT&CK index existence check, IOC type evidence gate, and IOC-technique compatibility check via a 282-technique allowlist with sub-technique parent fallback.
- **Hybrid Rule Generation** — Produces Wazuh XML detection rules across four categories: IOC-exact, blueprint-based, context-derived, and proactive. Blueprint dictionary built from Sigma Rules, Elastic Detection Rules, MITRE ATT&CK detection notes, and Wazuh documentation.
- **Risk Scoring** — Three-component scoring: external reputation (35%), technique severity (40%), kill chain position (25%). Scored 0–100, mapped to Clean / Low / Medium / High / Critical.
- **Confidence Scoring** — Evaluates JSON structural validity, technique ID format correctness, reasoning quality, and IOC-tactic alignment.
- **APT Projection** — Matches validated techniques to known APT groups from the ATT&CK STIX bundle. Analyst selects a candidate group, model predicts the next technique from a kill-chain-filtered candidate set, and proactive rules are generated for it.
- **Campaign Correlation** — Multi-IOC campaign mode aggregates techniques across all IOCs, identifies shared techniques, maps kill chain coverage as a heatmap, deduplicates rules into a unified set, and runs APT projection against the combined technique profile.
- **Role-Based Dashboards** — Analyst and admin interfaces with JWT authentication. Admins see all submissions, all rules, and system-wide statistics. Analysts see their own submissions, campaigns, and results.
- **Live Wazuh Validation** — Generated rules were validated against a live Wazuh instance on a Kali Linux VM, confirming end-to-end alert generation.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        FRONTEND                             │
│              React + TypeScript (Port 3000)                 │
│   Analyst Dashboard · Admin Dashboard · Campaign Mode       │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP (JWT)
┌────────────────────────▼────────────────────────────────────┐
│                        BACKEND                              │
│              FastAPI + Python (Port 8000)                   │
│  Enrichment · RAG Validation · Rule Generation · Scoring    │
│  APT Matching · Campaign Correlation · SQLite DB            │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP (ngrok tunnel)
┌────────────────────────▼────────────────────────────────────┐
│                     AI INFERENCE                            │
│         Foundation-Sec-8B-Instruct on Colab A100           │
│          Flask server · ATT&CK Mapping · APT Projection     │
└─────────────────────────────────────────────────────────────┘
```

---

## Three-Phase Pipeline

```
IOC Input
    │
    ▼
Phase 1 — Intelligence & Enrichment
    ├── IOC normalisation and type detection
    ├── Parallel API enrichment (VT · AbuseIPDB · Shodan · MalwareBazaar · URLScan)
    └── Analyst context collection
    │
    ▼
Phase 2 — MITRE Mapping & Rule Generation
    ├── Foundation-Sec-8B-Instruct → raw technique IDs + justifications
    ├── Backend RAG Validation (Rule 1: ATT&CK index · Rule 2: evidence gate · Rule 3: allowlist)
    ├── Technique enrichment via ATTACK_META_INDEX (name, tactics, description)
    ├── Hybrid rule generation (IOC-exact + blueprint + context-derived)
    ├── Confidence scoring (structure · format · reasoning · alignment)
    └── Risk scoring (reputation 35% + technique severity 40% + kill chain 25%)
    │
    ▼
Phase 3 — APT Projection & Proactive Defence
    ├── APT candidate identification from MITRE STIX bundle
    ├── Kill chain stage filtering (removes already-detected and earlier-stage techniques)
    ├── Next-technique prediction via Foundation-Sec-8B-Instruct
    ├── Proactive Wazuh XML rule generation for predicted technique
    └── Campaign correlation (shared techniques · kill chain heatmap · unified rules)
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend API | FastAPI (Python 3.10+) |
| Frontend | React 18 + TypeScript |
| Database | SQLite |
| AI Inference | Foundation-Sec-8B-Instruct via Hugging Face Transformers |
| Inference Host | Google Colab (A100 GPU) + Flask + ngrok |
| LLM Fallback | Anthropic Claude API |
| ATT&CK Data | MITRE ATT&CK Enterprise STIX Bundle |
| Rule Reference | Sigma Rules · Elastic Detection Rules · Wazuh Documentation |
| TI Enrichment | VirusTotal · AbuseIPDB · Shodan · MalwareBazaar · URLScan.io |
| Authentication | JWT (python-jose) |
| SIEM Target | Wazuh |
| Test Environment | Kali Linux VM (VirtualBox) |

---

## Repository Structure

```
Graduation_Project_ATT-CKsmith/
│
├── backend/
│   └── app/
│       ├── main.py                  # FastAPI application — full pipeline
│       ├── blueprints.py            # TECHNIQUE_BLUEPRINTS detection dictionary
│       ├── allowlist.json           # 282-technique IOC-type compatibility allowlist
│       ├── generate_allowlist.py    # Script to regenerate allowlist.json
│       ├── generate_blueprints.py   # Script to regenerate blueprints from 4 sources
│       └── enterprise-attack.json   # MITRE ATT&CK Enterprise STIX bundle
│
├── frontend/
│   └── src/                         # React + TypeScript source
│       ├── components/              # UI components
│       ├── pages/                   # Route pages
│       └── ...
│
└── README.md
```

> **Note:** The Colab notebook is separately available — see the dissertation for the link.

---

## Installation & Setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- Google Colab account (for AI inference)
- ngrok account (free tier works)

---

### 1. Backend Setup

```bash
# Clone the repository
git clone https://github.com/mohamed-moheb/Graduation_Project_Mohamed.git
cd Graduation_Project_Mohamed/backend

# Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Create a `.env` file in the `backend/` directory:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SHODAN_API_KEY=your_shodan_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key_optional
COLAB_API_URL=https://your-ngrok-url.ngrok-free.app/run
ALLOWED_ORIGIN=http://localhost:3000
```

Start the backend:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Expected startup output:
```
IOC allowlist loaded: 282 techniques
MITRE loaded: 168 APT groups, 703 techniques, 703 in ATTACK_ID_SET
Uvicorn running on http://0.0.0.0:8000
```

---

### 2. Frontend Setup

```bash
cd ../frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

Frontend runs at `http://localhost:3000`

---

### 3. Colab Inference Server Setup

1. Open the Colab notebook (link in dissertation)
2. Connect to an A100 GPU runtime
3. Run all cells top to bottom in order:
   - Model loading (Foundation-Sec-8B-Instruct in float16)
   - MITRE ATT&CK index loading
   - Sigma rules loading
   - Blueprint and candidate rule generation functions
   - `full_pipeline` and `llm_only_map` function definitions
   - Flask server startup on port 8000
   - ngrok tunnel creation
4. Copy the ngrok public URL printed at the end
5. Update `COLAB_API_URL` in your backend `.env` with the new ngrok URL
6. Restart the backend

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `VT_API_KEY` | Recommended | VirusTotal API key for IOC reputation scoring |
| `ABUSEIPDB_API_KEY` | Recommended | AbuseIPDB API key for IP abuse confidence |
| `SHODAN_API_KEY` | Optional | Shodan API key for infrastructure data and CVEs |
| `ANTHROPIC_API_KEY` | Optional | Claude API key — fallback when Colab is unreachable |
| `COLAB_API_URL` | Required | Full ngrok tunnel URL pointing to Colab Flask `/run` endpoint |
| `ALLOWED_ORIGIN` | Optional | CORS origin for frontend (default: `*`) |

> All keys are stored as environment variables and never transmitted to the frontend. The system operates in a degraded mode if enrichment keys are missing — mapping still runs from analyst context alone.

---

## API Endpoints Reference

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/login` | Authenticate and receive JWT token |

### IOC Analysis
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/ioc/submit` | Submit IOC through full pipeline |
| POST | `/api/ioc/enrich` | Enrich IOC without mapping |
| POST | `/api/ioc/candidates` | Get APT candidates for mapped techniques |
| POST | `/api/ioc/apt-projection` | Run APT projection for a selected group |

### Submissions
| Method | Endpoint | Description |
|---|---|---|
| GET | `/submissions/mine` | Get current analyst's submissions |
| GET | `/submissions/all` | Get all submissions (admin only) |
| POST | `/submissions/check` | Check if IOC already submitted |
| POST | `/submissions/save` | Save a submission result |
| POST | `/submissions/save-apt-projection` | Save APT projection to submission |
| DELETE | `/submissions/{id}` | Delete a submission (admin only) |

### Campaigns
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/campaign/submit` | Submit multi-IOC campaign |
| GET | `/api/campaign/{id}` | Get campaign details and results |
| GET | `/api/campaigns/mine` | Get current analyst's campaigns |
| GET | `/api/campaigns/all` | Get all campaigns (admin only) |
| DELETE | `/api/campaign/{id}` | Delete a campaign (admin only) |
| POST | `/api/campaign/{id}/apt-projection` | Run APT projection on campaign |
| GET | `/api/campaign/{id}/apt-candidates` | Get APT candidates for campaign |

### System
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Backend and Colab connectivity check |
| GET | `/api/allowlist` | Serve IOC-technique allowlist to Colab |
| GET | `/submissions/stats` | Dashboard statistics |

---

## Default Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Admin |
| `analyst1` | `pass123` | Analyst |
| `analyst2` | `pass123` | Analyst |

> These are for development and testing only. Change all passwords before any deployment.

---

## RAG Validation

The backend runs a three-rule RAG validation layer on every raw LLM output before techniques reach the analyst:

**Rule 1 — ATT&CK Index Check**
Technique ID must exist in the set of current, non-revoked ATT&CK technique IDs loaded from the MITRE Enterprise STIX bundle at startup.

**Rule 2 — Evidence Gate**
The submitted IOC type must have at least one defined evidence category. Prevents technique mappings for IOC types with no observable evidence path.

**Rule 3 — IOC-Technique Compatibility**
Technique must be in the allowed set for the submitted IOC type via `allowlist.json` (282 techniques). Includes sub-technique parent fallback — if `T1059.009` is not in the allowlist, parent `T1059` restrictions are inherited. Techniques not listed pass through safely.

To regenerate the allowlist after adding new techniques:
```bash
cd backend/app
python generate_allowlist.py
```

---

## Scoring Methodology

### Risk Score (0–100)

```
Risk = (Reputation × 0.35) + (Technique Severity × 0.40) + (Kill Chain Position × 0.25)
```

| Range | Level |
|---|---|
| 85–100 | Critical |
| 65–84 | High |
| 40–64 | Medium |
| 1–39 | Low |
| 0 | Clean |

### Confidence Score

Evaluates four dimensions of LLM output quality: JSON structural validity, technique ID format correctness, reasoning quality (word count and specificity), and IOC-tactic alignment. Capped at 92% to reflect inherent model uncertainty.

---

## Wazuh Rule Validation

Generated Wazuh XML rules were validated on a live Wazuh instance running on a Kali Linux virtual machine. The `T1071.001` rule generated from an IP address IOC was deployed to the custom rules file, a synthetic log event was triggered replicating the described beaconing behaviour, and the Wazuh manager generated a matching alert confirming end-to-end functionality.

---

## Academic Context

This system was developed as a graduation research project answering the following research question:

> *How can enriched Indicators of Compromise be automatically mapped to MITRE ATT&CK techniques using an AI-driven pipeline, and how can these mappings be used to generate defensive rules for SOC deployment?*

The project bridges a gap identified in the literature: no prior work combined IOC enrichment, validated ATT&CK mapping, deployable rule generation, and predictive APT projection in a single integrated pipeline.

**Dissertation:** Available on request  
**Institution:** Coventry University – The Knowledge Hub Universities  
**Programme:** BSc Ethical Hacking and Cybersecurity  
**Academic Year:** 2025–2026

---

## Citation

If you reference this work, please cite:

```
Moheb, M. (2026). ATT&CKsmith: AI-Driven System for Mapping Indicators of Compromise
to MITRE ATT&CK Techniques and Orchestrating Defensive Rule Generation.
BSc Dissertation, Coventry University – The Knowledge Hub Universities.
```

---

## Disclaimer

ATT&CKsmith is a research prototype developed for academic purposes. All rule testing was conducted in a controlled virtual environment. The system poses no harm to real networks, systems, or individuals.
