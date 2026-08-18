# Secure Cloud Access Monitoring System

## SOC architecture and workflow

Authentication Event → API Gateway → Application Validation → Historical Behavioural Features → ML Prediction → Risk Scoring → Alert → Incident Correlation → SOC Investigation → Analyst Assignment → Resolution → Audit Log.

This academic/prototype SOC platform monitors authentication activity from multiple registered applications. The existing ML pipeline provides model probability, threat score, confidence, behavioural evidence and explanations; the SOC layer stores and presents those real outputs without inventing scores or explanations.

Phase 10 adds database-backed alert intelligence (deterministic severity: CRITICAL requires strong model/risk evidence plus an anomaly; HIGH requires strong model/risk or failure/repetition signals; MEDIUM captures moderate model/risk or behavioural anomalies), five-minute event fingerprints for alert idempotency, ten-minute incident correlation, investigation notes, assignment history, audit records, filtering, pagination, and SOC APIs.

Incident lifecycle transitions are: `NEW → ACKNOWLEDGED → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`; `CLOSED` is also allowed from active states where an analyst closes an investigation. Invalid transitions are rejected and every status or assignment change is audited.

Security controls include hashed passwords and API keys, authenticated application ingestion, per-application rate limiting, parameterized SQLite queries, authorization on administrative SOC APIs, and sanitized API errors. The API gateway validates registered application ownership before accepting events.

## Limitations and future work

The training dataset is synthetic, so this is not a production cybersecurity product and must not be used as the sole basis for access-control decisions. Future work includes production telemetry connectors, role/application-scoped analyst access, durable distributed rate limiting, asynchronous correlation, and a managed database/migration system.

## Phase 11 operation guide

### Problem statement and objective

Cloud applications need a single, explainable view of unusual authentication activity. This project receives authenticated login events from multiple registered applications, enriches them with historical behavioural features, runs the existing ML model, then creates deduplicated alerts and correlated analyst incidents. It is intended for education and prototype demonstrations, not autonomous enforcement.

### Architecture and data flow

Both the built-in login flow and `POST /api/v1/auth-events` use the shared event-processing service: validation → historical feature extraction → ML prediction → behavioural evidence and reasons → risk classification → alert fingerprinting → incident correlation → audit record. Application registry validation happens before ingestion, and an API key is hashed and matched to its own active application.

The alert fingerprint contains application ID, user ID, IP, device ID, risk level, and a five-minute time bucket. Thus retries of the same signature are idempotent, while a changed application, user, IP, device, risk, or later time bucket remains visible as a distinct alert. Alerts persist the actual model probability, threat score, prediction confidence, evidence, and prediction reasons where provided by the ML pipeline.

Incidents correlate active, related events for the same application and user within ten minutes. The lifecycle is `NEW → TRIAGED → INVESTIGATING → CONTAINED → RESOLVED`, with `FALSE_POSITIVE` available from an active investigation state. Assignment, status changes, and append-only investigation notes are audit logged.

### API and database architecture

SOC list/detail APIs are available under `/api/v1/soc/events`, `/api/v1/soc/alerts`, and `/api/v1/soc/incidents`; incident assignment, status, and notes use the matching incident subroutes. `/api/v1/applications` and `/api/v1/applications/<application_id>/summary` expose administrator-only application views. Responses are paginated with `page` and `per_page` (20, 50, or 100).

SQLite tables retain authentication events, security alerts, incidents, event links, incident notes, assignment history, and audit logs. Additive indexes support application, severity, status, fingerprint, and incident lookups.

### Security controls

Passwords and API keys are stored only as hashes. SOC APIs require an administrator session; ingestion requires an active application key matching the event application. Revoked or disabled applications are rejected, parameterized queries are used, and error responses avoid stack traces and secrets. Audit logs and notes have no normal edit/delete routes.

### Running and demonstrating

1. Install dependencies: `pip install -r requirements.txt`.
2. Start the application: `python app.py`.
3. Sign in as an administrator and open `/admin/soc-dashboard`.
4. Register an active application, then submit a valid event to `POST /api/v1/auth-events` with its `X-API-Key`.
5. Inspect the dashboard, incident list, and application summary. Use the SOC APIs while logged in to filter/paginate records, assign an incident, move it through the lifecycle, and add an append-only note.
6. Run verification: `python -m pytest tests/ -q`.

## Presentation overview

**Target users:** application administrators and SOC analysts who need a consolidated view of multi-application authentication activity. **Usefulness:** it makes per-event model output, behavioural context, alerts, correlated incidents, and analyst actions traceable in one workflow.

**Pages/screens:** login and registration, user dashboard, AI prediction, monitored applications, SOC dashboard, security events, alerts, incidents, incident detail/timeline, audit logs, analytics, and API documentation.

**Technology stack:** Python, Flask, SQLite, scikit-learn model artifacts, pandas feature processing, Jinja templates, Bootstrap/Chart.js assets where included by the existing UI, and pytest.

**Model evaluation:** model-performance metrics are shown separately from each prediction. Individual probability and confidence describe a specific event and must never be interpreted as model accuracy. Risk policy is LOW (informational), MEDIUM (analyst review), HIGH (immediate investigation), using the existing documented model/risk thresholds and historical behavioural evidence.

**Database design:** applications own API credentials and retain historical event references even when disabled or revoked. `auth_events` record ML outputs; `security_alerts` retain an idempotency fingerprint and linked incident ID; `incidents`, `incident_events`, `incident_notes`, `incident_assignments`, and `audit_logs` form the analyst evidence trail.

**Future work:** connect production telemetry, add organization/application-scoped analyst roles, use a managed database and migration tooling, add distributed rate limiting, and validate with real ethically collected data.

> The current ML pipeline is an academic prototype trained using synthetic/heuristic authentication data and should not be interpreted as production-grade cyberattack detection.
