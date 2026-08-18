# Phase 12 Demonstration Guide (5–10 minutes)

Use only locally generated development API keys. Do not paste a real key into slides, README files, or recordings.

## Step 1 — Start the Flask server

Run `python app.py` from the project directory, then visit `http://127.0.0.1:5000`.

## Step 2 — Login as administrator

Use the development administrator account configured in your local database. Do not display its password.

## Step 3 — Open SOC dashboard

Open **SOC Dashboard**. Explain that every KPI and recent event comes from SQLite, with an empty state when records do not exist.

## Step 4 — Show monitored applications

Open **Applications** and show each application’s event/risk counts and status. Create an active demonstration application if needed; copy its generated key only into a local terminal.

## Step 5 — Submit a normal external event

Submit an ISO-8601 event through `POST /api/v1/auth-events`, using its own `X-API-Key`. Use a known IP/device from earlier activity for a normal-context example. The API documentation page has a safe request shape.

## Step 6 — Show the event in SOC

Refresh the dashboard or open security events. Point out timestamp, application, IP/device, model probability, threat score, and persisted behavioural evidence.

## Step 7 — Submit suspicious activity

For the same registered application, use a different valid documentation IP, a new device ID, off-hours timestamp, and recent failed-attempt count. The model—not the UI—determines probability, score, risk, reasons, alert, and incident eligibility.

## Step 8 — Explain the prediction

Open the event/alert record. Show behavioural evidence, model probability, threat score, risk level, and reasons. Do not describe individual confidence as model accuracy.

## Step 9 — Show correlated incident

Submit related suspicious activity inside the ten-minute correlation window, then open the incident. Show linked events, alerts, timeline, first/last seen, and event count. Explain fingerprint deduplication uses application, user, IP, device, risk, and a five-minute bucket.

## Step 10 — Assign an analyst

Assign the incident to a registered administrator/analyst account. Show the assignment history and audit record.

## Step 11 — Add investigation note

Add a concise note. Show that it appears chronologically and is append-only.

## Step 12 — Demonstrate lifecycle

Move the incident through `NEW → TRIAGED → INVESTIGATING → CONTAINED → RESOLVED`. In a separate incident, demonstrate `FALSE_POSITIVE`. Attempt an invalid transition and show the rejection.

## Step 13 — Show audit trail

Open the incident timeline/audit logs to show status, assignment, and note actions with actor and timestamp.

## Step 14 — Demonstrate isolation

Create a second application and attempt to submit an event naming it while using the first app’s key. The API returns `403`; application summaries show only their own events, alerts, and incidents.
