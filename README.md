# Adaptive Dynamic Threat Response System (DTRS)
## Microservices Architecture — v2.0

This project is structured as **6 independent microservices** that communicate over HTTP.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              LOCAL MACHINE                                     │
│                                                                                │
│  ┌─────────────┐  POST snapshot  ┌─────────────────────────────────────────┐  │
│  │    Agent    │ ──────────────▶ │      Detection Engine (5001)             │  │
│  │  (agent/)   │ ◀─── actions ── │  • Uses Policy Engine for rules (30s)   │  │
│  └─────────────┘                 │  • Fires webhooks via Notif. Service     │  │
│                                  └────┬──────────────┬────────────────┬────┘  │
│                                       │              │                │        │
│                    ┌──────────────────┘              │                │        │
│                    │                                 │                │        │
│  ┌─────────────────▼───┐   ┌──────────────────┐  ┌──▼─────────────┐  │        │
│  │  Notification Svc   │   │  Analytics Svc   │  │  Policy Engine  │  │        │
│  │  (5002)             │   │  (5003)          │  │  (5004)         │  │        │
│  │                     │   │                  │  │                 │  │        │
│  │ • Slack webhooks    │   │ • Top offenders  │  │ • CPU thresholds│  │        │
│  │ • Discord webhooks  │   │ • CPU trends     │  │ • Process rules │  │        │
│  │ • Teams webhooks    │   │ • Alert heatmaps │  │ • Cooldowns     │  │        │
│  │ • Generic HTTP      │   │ • Risk breakdown │  │ • Auto-WL config│  │        │
│  └─────────────────────┘   └──────────────────┘  └─────────────────┘  │        │
│                                       │                                │        │
│                           ┌───────────▼────────────┐                  │        │
│                           │   Dashboard  (5000)     │                  │        │
│                           │  • Process monitor      │                  │        │
│                           │  • Alerts & actions     │                  │        │
│                           │  • Analytics tab        │                  │        │
│                           │  • Policy config UI     │                  │        │
│                           │  • Notifications UI     │                  │        │
│                           └─────────────────────────┘                  │        │
│                                       ▲                                │        │
│                                       │ Browser                        │        │
│                                   👤 User                              │        │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Services

| Service | Directory | Port | Description |
|---|---|---|---|
| **Detection Engine** | `detection_engine/` | `5001` | Core risk engine, state, storage, action queue |
| **Web Dashboard** | `dashboard/` | `5000` | Stateless HTML frontend (all tabs) |
| **Agent** | `agent/` | — | Local process collector & action executor |
| **Notification Service** | `notification_service/` | `5002` | Webhook alerts (Slack/Discord/Teams/Generic) |
| **Analytics Service** | `analytics_service/` | `5003` | Threat intelligence, trends, heatmaps |
| **Policy Engine** | `policy_engine/` | `5004` | Runtime rules: thresholds, per-process, cooldowns |

---

## 🚀 Running Locally (without Docker)

Open **6 separate terminals**:

**Terminal 1 – Policy Engine (start first, Detection Engine depends on it):**
```bash
cd policy_engine
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5004
```

**Terminal 2 – Detection Engine:**
```bash
cd detection_engine
pip install -r requirements.txt
set POLICY_ENGINE_URL=http://localhost:5004
set NOTIFICATION_SERVICE_URL=http://localhost:5002
python app.py
# Runs on http://localhost:5001
```

**Terminal 3 – Notification Service:**
```bash
cd notification_service
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5002
```

**Terminal 4 – Analytics Service:**
```bash
cd analytics_service
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5003
```

**Terminal 5 – Web Dashboard:**
```bash
cd dashboard
pip install -r requirements.txt
set DETECTION_ENGINE_URL=http://localhost:5001
set ANALYTICS_SERVICE_URL=http://localhost:5003
set POLICY_ENGINE_URL=http://localhost:5004
set NOTIFICATION_SERVICE_URL=http://localhost:5002
python app.py
# Runs on http://localhost:5000
```

**Terminal 6 – Agent (on the machine to monitor):**
```bash
cd agent
pip install -r requirements.txt
set DETECTION_ENGINE_URL=http://localhost:5001
set DASHBOARD_URL=http://localhost:5000
python agent.py
```

Then open **http://localhost:5000** in your browser.

---

## 🐳 Running with Docker Compose

```bash
docker-compose up --build
```

This will build and start all **6 services** with correct inter-service wiring.

> **Note:** On Linux/Docker Desktop, `pid: host` in docker-compose allows the Agent container to see and terminate host processes. On Windows Docker Desktop, the Agent should run natively with `python agent/agent.py`.

---

## 🌐 Public Deployment Options

Since the **Dashboard** is completely stateless and all state lives in other services:

### Option A: Ngrok Tunnel (Quickest)
```bash
# Start all 6 services locally, then:
ngrok http 5000
# Share the generated public URL
```

### Option B: Deploy Dashboard to Vercel/Render
- Deploy `dashboard/` to Vercel or Render
- Set env vars pointing to your server IPs for all 4 backend services

### Option C: Full Cloud (VPS)
- Run all 6 services via Docker Compose on a VPS (e.g., DigitalOcean, AWS EC2)

---

## ⚙️ Environment Variables

| Service | Variable | Default | Description |
|---|---|---|---|
| Detection Engine | `PORT` | `5001` | Listening port |
| Detection Engine | `DATA_DIR` | `.` | Directory for JSON storage |
| Detection Engine | `POLICY_ENGINE_URL` | `http://localhost:5004` | Policy Engine URL |
| Detection Engine | `NOTIFICATION_SERVICE_URL` | `http://localhost:5002` | Notification Service URL |
| Dashboard | `PORT` | `5000` | Listening port |
| Dashboard | `DETECTION_ENGINE_URL` | `http://localhost:5001` | Detection Engine URL |
| Dashboard | `ANALYTICS_SERVICE_URL` | `http://localhost:5003` | Analytics Service URL |
| Dashboard | `POLICY_ENGINE_URL` | `http://localhost:5004` | Policy Engine URL |
| Dashboard | `NOTIFICATION_SERVICE_URL` | `http://localhost:5002` | Notification Service URL |
| Dashboard | `FLASK_SECRET` | `dtrs-dashboard-secret-2025` | Flask session secret |
| Agent | `DETECTION_ENGINE_URL` | `http://localhost:5001` | Detection Engine URL |
| Agent | `DASHBOARD_URL` | `http://localhost:5000` | Dashboard URL (for toast links) |
| Agent | `SCAN_INTERVAL` | `3` | Seconds between process scans |
| Agent | `ACTION_INTERVAL` | `2` | Seconds between action polls |
| Notification Service | `PORT` | `5002` | Listening port |
| Notification Service | `DATA_DIR` | `.` | Config storage directory |
| Analytics Service | `PORT` | `5003` | Listening port |
| Analytics Service | `DATA_DIR` | `.` | Must point to same dir as Detection Engine logs |
| Policy Engine | `PORT` | `5004` | Listening port |
| Policy Engine | `DATA_DIR` | `.` | Policy storage directory |

---

## 🔔 Setting Up Webhook Notifications

1. Open `http://localhost:5000/notifications`
2. Select your platform (Slack / Discord / Teams / Generic)
3. Follow the on-screen guide to get your webhook URL
4. Paste the URL, give it a name, and click **Add Webhook**
5. Click **🧪** to send a test alert and verify delivery

---

## ⚙️ Configuring Detection Policy

1. Open `http://localhost:5000/policy`
2. **CPU Thresholds**: Set where LOW/MEDIUM/HIGH boundaries fall
3. **Settings**: Adjust alert cooldown duration and auto-whitelist threshold
4. **Per-Process Rules**: Pin specific processes to always ignore, alert, or terminate

Changes take effect in the Detection Engine within **30 seconds** (no restart needed).

---

## 📈 Analytics

Open `http://localhost:5000/analytics` to see:
- **Summary stats**: total events, alerts, terminations, alert rate
- **CPU Trend chart**: 30-minute bucketed CPU spikes over the last 24 hours
- **Top Threat Actors**: ranked by threat score (alerts × 3 + terminations × 2)
- **Alert Heatmap**: hour-of-day × day-of-week frequency grid
- **Risk Distribution**: donut chart of HIGH / MEDIUM / LOW events
