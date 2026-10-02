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

Passwords and API keys are stored only as SHA-256 / Werkzeug hashes. Role-based authorization controls access to administrative functions (`role="admin"`) and SOC operations (`role in ('admin', 'analyst')`). Ingestion requires an active application key matching the event application. Revoked or disabled applications are rejected, parameterized queries are used, and error responses avoid stack traces and secrets. Audit logs and notes have no normal edit/delete routes.

## Forgot Password Email OTP Flow & SMTP Configuration

The system uses a secure 6-digit Email OTP (One-Time Password) workflow for password recovery:

1. **OTP Generation & Anti-Enumeration**: When a user submits their email on `/forgot-password`, a cryptographically secure 6-digit numeric OTP (`secrets.randbelow`) is generated. Registered and unregistered emails receive identical generic success responses to prevent user enumeration attacks.
2. **SHA-256 Hashed Storage**: The plaintext OTP is never saved to the database. Only a SHA-256 digest (`otp_hash`) is stored in the `password_reset_otps` table.
3. **10-Minute Expiry & Single-Use**: OTP codes expire after 10 minutes (`RESET_OTP_TTL_MINUTES = 10`). Requesting a new OTP automatically invalidates all previous unused OTPs for that user account.
4. **Attempt Rate Limiting**: The verification endpoint (`/verify-otp`) allows a maximum of 5 failed OTP attempts. If the 5-attempt threshold is reached, the OTP is permanently invalidated to block brute-force guessing.
5. **Rate Limiting**: IP-based and email-based rate limits permit a maximum of 5 OTP reset requests per hour per client.
6. **Password Reset & Account Unlocking**: Upon entering the valid 6-digit code on `/verify-otp`, the user is redirected to `/reset-password`. Successfully changing the password updates the hashed password, resets failed attempt counters, unlocks locked accounts (`account_locked = 0`), and invalidates the single-use OTP.

### Gmail SMTP & Development Mode Configuration

Email delivery automatically selects between Real SMTP Delivery and Development Mode:

- **Real Gmail SMTP Delivery**: Set environment variables in `.env`:
  ```env
  MAIL_SERVER=smtp.gmail.com
  MAIL_PORT=587
  MAIL_USE_TLS=true
  MAIL_USERNAME=your-email@gmail.com
  MAIL_PASSWORD=your-gmail-app-password
  MAIL_DEFAULT_SENDER=your-email@gmail.com
  ```
  STARTTLS on port 587 sends real 6-digit OTP emails to users. `MAIL_PASSWORD` is strictly protected and never exposed in logs or diagnostic APIs.
- **Development Mode Sink**: If `MAIL_SERVER` is omitted or empty in `.env`, the app operates safely in `[DEV MODE]`. OTP emails are redirected to `app.config['MAIL_OUTBOX']`, allowing full local testing without an SMTP server.

### Running and demonstrating

1. Install dependencies: `pip install -r requirements.txt`.
2. Start the application: `python app.py`.
3. Sign in as an administrator and open `/admin/soc-dashboard`.
4. Register an active application, then submit a valid event to `POST /api/v1/auth-events` with its `X-API-Key`.
5. Inspect the dashboard, incident list, and application summary. Use the SOC APIs while logged in to filter/paginate records, assign an incident, move it through the lifecycle, and add an append-only note.
6. Test Forgot Password OTP flow: visit `/forgot-password`, enter a registered user email, retrieve the 6-digit code (from email inbox or Flask log / `MAIL_OUTBOX`), verify it on `/verify-otp`, and set a new password on `/reset-password`.
7. Run verification: `python -m pytest -v`.

## Presentation overview

**Target users:** application administrators and SOC analysts who need a consolidated view of multi-application authentication activity. **Usefulness:** it makes per-event model output, behavioural context, alerts, correlated incidents, analyst actions, and secure user recovery traceable in one workflow.

**Pages/screens:** login and registration, forgot password, verify OTP, reset password, user dashboard, AI prediction, monitored applications, SOC dashboard, security events, alerts, incidents, incident detail/timeline, audit logs, analytics, and API documentation.

**Technology stack:** Python, Flask, SQLite, scikit-learn model artifacts, pandas feature processing, Jinja templates, Bootstrap/Chart.js assets where included by the existing UI, and pytest.

**Model evaluation:** model-performance metrics are shown separately from each prediction. Individual probability and confidence describe a specific event and must never be interpreted as model accuracy. Risk policy is LOW (informational), MEDIUM (analyst review), HIGH (immediate investigation), using the existing documented model/risk thresholds and historical behavioural evidence.

**Database design:** applications own API credentials and retain historical event references even when disabled or revoked. `auth_events` record ML outputs; `security_alerts` retain an idempotency fingerprint and linked incident ID; `password_reset_otps` store SHA-256 hashed 6-digit OTPs with 10-minute TTL and attempt counts; `users` table includes lower-case email index `idx_users_email_lower`; `incidents`, `incident_events`, `incident_notes`, `incident_assignments`, and `audit_logs` form the analyst evidence trail.

**Future work:** connect production telemetry, add organization/application-scoped analyst roles, use a managed database and migration tooling, add distributed rate limiting, and validate with real ethically collected data.

> The current ML pipeline is an academic prototype trained using synthetic/heuristic authentication data and should not be interpreted as production-grade cyberattack detection.
