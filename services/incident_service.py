"""
services/incident_service.py — Incident management and correlation logic for Phase 9 SOC monitoring.
"""
import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database.db")

LIFECYCLE_TRANSITIONS = {
    "NEW": {"TRIAGED", "ACKNOWLEDGED", "FALSE_POSITIVE", "CLOSED"},
    "TRIAGED": {"INVESTIGATING", "FALSE_POSITIVE", "CLOSED"},
    "ACKNOWLEDGED": {"INVESTIGATING", "FALSE_POSITIVE", "CLOSED"},
    "INVESTIGATING": {"CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"},
    "CONTAINED": {"RESOLVED", "FALSE_POSITIVE", "CLOSED"},
    "RESOLVED": {"CLOSED"}, "FALSE_POSITIVE": {"CLOSED"}, "CLOSED": set(),
    # Existing Phase 9 data remains valid and can enter the lifecycle.
    "OPEN": {"TRIAGED", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "CLOSED"},
}


def _audit(cursor, actor, action, description, ip_address=""):
    cursor.execute("INSERT INTO audit_logs (user_id, username, action, timestamp, ip_address, description) VALUES (0, ?, ?, ?, ?, ?)",
                   (actor, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip_address, description))


def _generate_incident_id() -> str:
    """Generate a unique incident ID like INC-000123."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(CAST(SUBSTR(incident_id, 5) AS INTEGER)) FROM incidents")
    row = cursor.fetchone()
    conn.close()
    max_num = row[0] if row and row[0] else 0
    return f"INC-{str(max_num + 1).zfill(6)}"


def _correlate_related_events(application_id: str, username: str, ip_address: str, 
                               event_timestamp: str, time_window_minutes: int = 10) -> List[int]:
    """
    Find related events within a time window for correlation.
    
    Criteria:
    - Same application
    - Same user
    - Same IP or same device
    - Within time_window_minutes
    
    Returns list of event IDs that should be part of the same incident.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            SELECT id FROM auth_events
            WHERE application_id = ?
              AND username = ?
              AND ip_address = ?
              AND datetime(timestamp) > datetime(?, '-' || ? || ' minutes')
              AND datetime(timestamp) < datetime(?, '+' || ? || ' minutes')
            """,
            (application_id, username, ip_address, event_timestamp, time_window_minutes,
             event_timestamp, time_window_minutes),
        )
        return [row["id"] for row in cursor.fetchall()]
    finally:
        conn.close()


def create_or_update_incident(application_id: str, event_id: int, username: str, 
                               ip_address: str, risk_level: str, event_timestamp: str,
                               threat_score: float, prediction: str, 
                               reasons: List[str], confidence: float) -> Optional[str]:
    """
    Create a new incident or update an existing one based on risk level and event correlation.
    
    Logic:
    - LOW: no incident
    - MEDIUM: create alert (handled elsewhere)
    - HIGH: create incident
    - CRITICAL: create incident (if thresholds allow)
    
    Returns: incident_id (new or existing) or None if no incident was created.
    """
    
    # Only create incidents for MEDIUM+ risk
    if risk_level not in {"MEDIUM", "HIGH", "CRITICAL"}:
        return None
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Check if an open/investigating incident exists for this user/app/IP within time window
        cursor.execute(
            """
            SELECT incident_id FROM incidents
            WHERE application_id = ?
              AND username = ?
              AND status IN ('NEW', 'OPEN', 'TRIAGED', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED')
              AND datetime(COALESCE(last_seen, created_at)) >= datetime(?, '-10 minutes')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (application_id, username, event_timestamp),
        )
        existing = cursor.fetchone()
        
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if existing:
            # Update existing incident
            incident_id = existing["incident_id"]
            severity = "CRITICAL" if risk_level == "CRITICAL" else "HIGH" if risk_level == "HIGH" else "MEDIUM"
            
            cursor.execute(
                """
                UPDATE incidents
                SET updated_at = ?, last_seen = ?, severity = CASE WHEN ? = 'CRITICAL' THEN 'CRITICAL' ELSE severity END
                WHERE incident_id = ?
                """,
                (now_str, event_timestamp, severity, incident_id),
            )
        else:
            # Create new incident
            incident_id = _generate_incident_id()
            severity = "CRITICAL" if risk_level == "CRITICAL" else "HIGH" if risk_level == "HIGH" else "MEDIUM"
            
            title = f"{severity} Risk Event: {username} from {ip_address}"
            description = f"{prediction} event detected. Threat score: {threat_score:.1f}. Confidence: {confidence:.1f}%."
            
            cursor.execute(
                """
                INSERT INTO incidents 
                (incident_id, application_id, user_id, username, severity, title, description, 
                 status, created_at, updated_at, first_seen, last_seen, source_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'NEW', ?, ?, ?, ?, ?)
                """,
                (incident_id, application_id, username, username, severity, title, description,
                now_str, now_str, event_timestamp, event_timestamp, ip_address),
            )
        
        # Link the event to the incident (if not already linked)
        cursor.execute(
            """
            SELECT COUNT(*) as cnt FROM incident_events
            WHERE incident_id = ? AND event_id = ?
            """,
            (incident_id, event_id),
        )
        if cursor.fetchone()["cnt"] == 0:
            cursor.execute(
                """
                INSERT INTO incident_events (incident_id, event_id, application_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (incident_id, event_id, application_id, now_str),
            )
        
        conn.commit()
        return incident_id
    finally:
        conn.close()


def get_incident_by_id(incident_id: str) -> Optional[Dict]:
    """Retrieve a single incident with all details."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        
        # Fetch related events
        cursor.execute(
            """
            SELECT ae.* FROM auth_events ae
            JOIN incident_events ie ON ae.id = ie.event_id
            WHERE ie.incident_id = ?
            ORDER BY ae.timestamp DESC
            """,
            (incident_id,),
        )
        events = [dict(e) for e in cursor.fetchall()]
        notes = [dict(e) for e in cursor.execute("SELECT * FROM incident_notes WHERE incident_id=? ORDER BY created_at", (incident_id,)).fetchall()]
        assignments = [dict(e) for e in cursor.execute("SELECT * FROM incident_assignments WHERE incident_id=? ORDER BY assigned_at", (incident_id,)).fetchall()]
        alerts = [dict(e) for e in cursor.execute("SELECT * FROM security_alerts WHERE incident_id=? ORDER BY created_at", (incident_id,)).fetchall()]
        audit = [dict(e) for e in cursor.execute("SELECT * FROM audit_logs WHERE description LIKE ? ORDER BY timestamp", (f"%{incident_id}%",)).fetchall()]
        timeline = ([{"type": "event", "timestamp": e.get("timestamp"), "data": e} for e in events] +
                    [{"type": "alert", "timestamp": a.get("created_at"), "data": a} for a in alerts] +
                    [{"type": "note", "timestamp": n.get("created_at"), "data": n} for n in notes] +
                    [{"type": "audit", "timestamp": a.get("timestamp"), "data": a} for a in audit])
        timeline.sort(key=lambda item: item["timestamp"] or "")
        
        return {
            "incident_id": row["incident_id"],
            "application_id": row["application_id"],
            "username": row["username"],
            "severity": row["severity"],
            "title": row["title"],
            "description": row["description"],
            "status": row["status"],
            "assigned_to": row["assigned_to"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "resolved_at": row["resolved_at"],
            "resolution_notes": row["resolution_notes"],
            "events": events,
            "event_count": len(events),
            "notes": notes,
            "assignments": assignments,
            "alerts": alerts,
            "alert_count": len(alerts),
            "timeline": timeline,
        }
    finally:
        conn.close()


def list_incidents(filters: Optional[Dict] = None, limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
    """
    List incidents with optional filters.
    
    Filters can include:
    - severity: LOW, MEDIUM, HIGH, CRITICAL
    - status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    - application_id
    - username
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if filters:
            if filters.get("severity"):
                query += " AND severity = ?"
                params.append(filters["severity"])
            if filters.get("status"):
                query += " AND status = ?"
                params.append(filters["status"])
            if filters.get("application_id"):
                query += " AND application_id = ?"
                params.append(filters["application_id"])
            if filters.get("username"):
                query += " AND username = ?"
                params.append(filters["username"])
        
        # Get total count
        count_query = f"SELECT COUNT(*) as cnt FROM ({query})"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()["cnt"]
        
        # Get paginated results
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        cursor.execute(query, params + [limit, offset])
        
        incidents = [dict(row) for row in cursor.fetchall()]
        
        # Fetch event count for each incident
        for inc in incidents:
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM incident_events WHERE incident_id = ?",
                (inc["incident_id"],),
            )
            inc["event_count"] = cursor.fetchone()["cnt"]
        
        return incidents, total_count
    finally:
        conn.close()


def update_incident_status(incident_id: str, new_status: str, resolution_notes: str = "", actor: str = "system", comment: str = "") -> bool:
    """
    Update incident status. Valid statuses: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    """
    if new_status not in LIFECYCLE_TRANSITIONS:
        return False
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        row = cursor.execute("SELECT status FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not row or new_status not in LIFECYCLE_TRANSITIONS.get(row[0], set()):
            return False
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        resolved_at = now_str if new_status in {"RESOLVED", "CLOSED", "FALSE_POSITIVE"} else None
        
        cursor.execute(
            """
            UPDATE incidents
            SET status = ?, updated_at = ?, resolved_at = ?, resolution_notes = ?
            WHERE incident_id = ?
            """,
            (new_status, now_str, resolved_at, resolution_notes, incident_id),
        )
        if new_status == "ACKNOWLEDGED":
            cursor.execute("UPDATE incidents SET acknowledged_at=? WHERE incident_id=?", (now_str, incident_id))
        _audit(cursor, actor, "incident_status_changed", f"Incident {incident_id}: {row[0]} -> {new_status}. {comment}".strip())
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def assign_incident(incident_id: str, assigned_to: str, assigned_by: str = "system") -> bool:
    """Assign an incident to a user."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            """
            UPDATE incidents
            SET assigned_to = ?, updated_at = ?
            WHERE incident_id = ?
            """,
            (assigned_to, now_str, incident_id),
        )
        if cursor.rowcount:
            cursor.execute("UPDATE incidents SET assigned_at=? WHERE incident_id=?", (now_str, incident_id))
            cursor.execute("INSERT INTO incident_assignments (incident_id, assigned_to, assigned_by, assigned_at) VALUES (?, ?, ?, ?)",
                           (incident_id, assigned_to, assigned_by, now_str))
            _audit(cursor, assigned_by, "incident_assigned", f"Incident {incident_id} assigned to {assigned_to}")
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def add_incident_note(incident_id: str, analyst: str, note: str) -> bool:
    """Notes are append-only; each entry is independently timestamped and audited."""
    note = (note or "").strip()
    if not note or len(note) > 5000:
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        if not cursor.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone():
            return False
        cursor.execute("INSERT INTO incident_notes (incident_id, analyst, note, created_at) VALUES (?, ?, ?, ?)",
                       (incident_id, analyst, note, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        _audit(cursor, analyst, "incident_note_added", f"Note added to incident {incident_id}")
        conn.commit()
        return True
    finally:
        conn.close()


def get_soc_metrics() -> Dict:
    conn = sqlite3.connect(DB_PATH)
    try:
        acknowledge = conn.execute("SELECT AVG((julianday(acknowledged_at)-julianday(created_at))*86400) FROM incidents WHERE acknowledged_at IS NOT NULL").fetchone()[0]
        resolve = conn.execute("SELECT AVG((julianday(resolved_at)-julianday(created_at))*86400) FROM incidents WHERE resolved_at IS NOT NULL").fetchone()[0]
        return {"mtta_seconds": acknowledge, "mttr_seconds": resolve}
    finally:
        conn.close()


def get_soc_summary() -> Dict:
    """Get a summary of SOC metrics for dashboard."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Total events today
        today_events = cursor.execute(
            "SELECT COUNT(*) as cnt FROM auth_events WHERE DATE(timestamp) = DATE('now')"
        ).fetchone()["cnt"]
        
        # Open incidents
        open_incidents = cursor.execute(
            "SELECT COUNT(*) as cnt FROM incidents WHERE status = 'OPEN'"
        ).fetchone()["cnt"]
        
        # Critical incidents
        critical_incidents = cursor.execute(
            "SELECT COUNT(*) as cnt FROM incidents WHERE severity = 'CRITICAL' AND status != 'RESOLVED'"
        ).fetchone()["cnt"]
        
        # High-risk events today
        high_risk_today = cursor.execute(
            "SELECT COUNT(*) as cnt FROM auth_events WHERE risk_level = 'HIGH' AND DATE(timestamp) = DATE('now')"
        ).fetchone()["cnt"]
        
        # Medium-risk events today
        medium_risk_today = cursor.execute(
            "SELECT COUNT(*) as cnt FROM auth_events WHERE risk_level = 'MEDIUM' AND DATE(timestamp) = DATE('now')"
        ).fetchone()["cnt"]
        
        # Alerts requiring investigation
        requiring_investigation = cursor.execute(
            "SELECT COUNT(*) as cnt FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING')"
        ).fetchone()["cnt"]
        
        # Applications monitored
        apps_monitored = cursor.execute(
            "SELECT COUNT(*) as cnt FROM applications"
        ).fetchone()["cnt"]
        
        # Active applications
        apps_active = cursor.execute(
            "SELECT COUNT(*) as cnt FROM applications WHERE status = 'active'"
        ).fetchone()["cnt"]
        
        total_events = cursor.execute("SELECT COUNT(*) as cnt FROM auth_events").fetchone()["cnt"]
        risk_counts = {r: cursor.execute("SELECT COUNT(*) AS cnt FROM auth_events WHERE risk_level=?", (r,)).fetchone()["cnt"] for r in ("HIGH", "MEDIUM", "LOW")}
        status_counts = {s: cursor.execute("SELECT COUNT(*) AS cnt FROM incidents WHERE status=?", (s,)).fetchone()["cnt"] for s in ("NEW", "OPEN", "INVESTIGATING", "RESOLVED")}
        high_alerts = cursor.execute("SELECT COUNT(*) AS cnt FROM security_alerts WHERE severity IN ('HIGH','CRITICAL')").fetchone()["cnt"]
        medium_alerts = cursor.execute("SELECT COUNT(*) AS cnt FROM security_alerts WHERE severity='MEDIUM'").fetchone()["cnt"]
        false_positives = cursor.execute("SELECT COUNT(*) AS cnt FROM incidents WHERE status='FALSE_POSITIVE'").fetchone()["cnt"]
        events_24h = cursor.execute("SELECT COUNT(*) AS cnt FROM auth_events WHERE datetime(timestamp) >= datetime('now', '-24 hours')").fetchone()["cnt"]
        return {
            "total_events_today": today_events,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "high_risk_events_today": high_risk_today,
            "medium_risk_events_today": medium_risk_today,
            "requiring_investigation": requiring_investigation,
            "apps_monitored": apps_monitored,
            "apps_active": apps_active,
            "events_received": total_events, "high_risk_events": risk_counts["HIGH"], "medium_risk_events": risk_counts["MEDIUM"], "low_risk_events": risk_counts["LOW"],
            "investigating_incidents": status_counts["INVESTIGATING"], "resolved_incidents": status_counts["RESOLVED"],
            "events_last_24_hours": events_24h, "high_alerts": high_alerts, "medium_alerts": medium_alerts,
            "false_positives": false_positives,
        }
    finally:
        conn.close()


def get_recent_events(limit: int = 25) -> List[Dict]:
    """Get recent security events for the SOC event feed."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            SELECT ae.id, ae.application_id, ae.username, ae.timestamp, ae.ip_address,
                   ae.device_id, ae.browser, ae.risk_level, ae.risk_score, ae.prediction,
                   ae.model_probability, ae.confidence, ae.behavioural_evidence, ae.status, ae.login_success
            FROM auth_events ae
            ORDER BY ae.timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_top_risky_users(limit: int = 10, days: int = 7) -> List[Dict]:
    """Get top risky users based on high/medium risk events in recent days."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            SELECT username, COUNT(*) as event_count, 
                   SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk_count,
                   SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk_count,
                   MAX(timestamp) as last_event
            FROM auth_events
            WHERE DATE(timestamp) >= DATE('now', '-' || ? || ' days')
              AND risk_level IN ('HIGH', 'MEDIUM')
            GROUP BY username
            ORDER BY event_count DESC
            LIMIT ?
            """,
            (days, limit),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_top_risky_ips(limit: int = 10, days: int = 7) -> List[Dict]:
    """Get top risky IPs based on high/medium risk events in recent days."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            SELECT ip_address, COUNT(*) as event_count,
                   SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk_count,
                   SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk_count,
                   COUNT(DISTINCT username) as unique_users,
                   MAX(timestamp) as last_event
            FROM auth_events
            WHERE DATE(timestamp) >= DATE('now', '-' || ? || ' days')
              AND risk_level IN ('HIGH', 'MEDIUM')
            GROUP BY ip_address
            ORDER BY event_count DESC
            LIMIT ?
            """,
            (days, limit),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()
